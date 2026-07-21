// Package s3 is a MINIMAL, standard-library-only S3 client for pushing encrypted
// backup blobs to S3-compatible object storage (AWS S3, MinIO, Cloudflare R2,
// Backblaze B2). It exists so Mooring can offer off-box backups WITHOUT pulling the
// AWS SDK — or any third-party module — into a security-first project's dependency
// set. Everything here is net/http + crypto/{hmac,sha256} + encoding/{hex,xml}.
//
// Security posture:
//   - Request signing is AWS Signature Version 4, hand-implemented in sign.go and
//     pinned by a known-answer test against the AWS-documented example vectors, so a
//     signing regression fails the build rather than silently corrupting auth.
//   - Uploads use x-amz-content-sha256: UNSIGNED-PAYLOAD, which is valid over TLS and
//     lets Put STREAM the body — the backup is never hashed or buffered in RAM. Upload is a
//     SINGLE PUT (no multipart yet), so objects over 5 GiB are rejected on AWS; MinIO/R2/B2
//     have higher/no single-PUT caps.
//   - The secret key and the Authorization header are never logged (this package logs
//     nothing at all) and never appear in returned errors.
//   - HTTPS by default; plain http is opt-in (Config.Insecure) for MinIO on a trusted
//     private network.
package s3

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes the target bucket and credentials. UsePathStyle defaults the
// caller toward path-style URLs (https://endpoint/bucket/key), which every
// S3-compatible server understands; virtual-host style is secondary.
type Config struct {
	Endpoint        string // host[:port], e.g. "s3.us-east-1.amazonaws.com" or "minio.example.com:9000"
	Region          string // e.g. "us-east-1"
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	UsePathStyle    bool // true (recommended) for MinIO/most S3-compatible; virtual-host when false
	Insecure        bool // allow http:// (MinIO on a private network); default false = https
}

// Object is one listed object.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// Client is a signing S3 client bound to one bucket. Safe for concurrent use (it
// holds only immutable config plus an *http.Client).
type Client struct {
	cfg Config
	hc  *http.Client
}

// New validates cfg and returns a Client. A nil hc gets a sane default transport with
// per-phase timeouts (dial/TLS/response-header) but NO whole-request Timeout: a
// multi-GB upload legitimately streams for many minutes, so request cancellation is
// left to the caller's context instead of a blunt deadline that would abort big Puts.
func New(cfg Config, hc *http.Client) (*Client, error) {
	// Tolerate an endpoint pasted with a scheme or trailing slash.
	cfg.Endpoint = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(cfg.Endpoint, "https://"), "http://"), "/")

	switch {
	case cfg.Endpoint == "":
		return nil, errors.New("s3: endpoint required")
	case cfg.Region == "":
		return nil, errors.New("s3: region required")
	case cfg.Bucket == "":
		return nil, errors.New("s3: bucket required")
	case cfg.AccessKeyID == "" || cfg.SecretAccessKey == "":
		return nil, errors.New("s3: access key and secret key required")
	}

	if hc == nil {
		hc = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 5 * time.Minute,
				ExpectContinueTimeout: 5 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConns:          32,
			},
			// No Timeout: uploads stream; the ctx passed to each call cancels them.
		}
	}
	return &Client{cfg: cfg, hc: hc}, nil
}

// singlePutMax is AWS S3's single-PUT object-size ceiling (5 GiB). Larger objects require
// multipart upload, which this client does not implement yet.
const singlePutMax = 5 << 30

// Put uploads exactly size bytes read from r to key. The body is streamed (never fully
// buffered) using UNSIGNED-PAYLOAD signing. contentType may be "". Objects over 5 GiB are
// rejected (single PUT only; no multipart yet).
func (c *Client) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	if key == "" {
		return errors.New("s3: put: empty key")
	}
	if size < 0 {
		return errors.New("s3: put: negative size")
	}
	// A single PUT is capped at 5 GiB on AWS S3 (S3-compatible stores vary). This client does a
	// single PUT (no multipart yet), so fail early with a clear message rather than a raw 400
	// EntityTooLarge from the server after streaming the whole body.
	if size > singlePutMax {
		return fmt.Errorf("s3: object is %d bytes, over the %d-byte single-PUT limit (multipart upload is not yet implemented)", size, int64(singlePutMax))
	}
	u := c.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), r)
	if err != nil {
		return fmt.Errorf("s3: put: %w", err)
	}
	req.URL = u // preserve our exact RawPath encoding (don't trust a re-parse round-trip)
	req.ContentLength = size
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	c.sign(req, unsignedPayload)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("s3: put %q: %w", key, err)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return responseError("put "+key, resp)
	}
	return nil
}

// Delete removes key. It is idempotent: a 404 (already gone) is not an error.
func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("s3: delete: empty key")
	}
	u := c.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("s3: delete: %w", err)
	}
	req.URL = u
	c.sign(req, unsignedPayload)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("s3: delete %q: %w", key, err)
	}
	defer drainClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return responseError("delete "+key, resp)
	}
}

// maxListPage bounds a single ListObjectsV2 XML response so a hostile/broken endpoint
// can't OOM the box. A full 1000-key page is well under this.
const maxListPage = 16 << 20

// List returns every object under prefix, following ListObjectsV2 continuation tokens
// across as many pages as needed. prefix "" lists the whole bucket.
func (c *Client) List(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	token := ""
	for {
		params := [][2]string{{"list-type", "2"}}
		if prefix != "" {
			params = append(params, [2]string{"prefix", prefix})
		}
		if token != "" {
			params = append(params, [2]string{"continuation-token", token})
		}
		u := c.bucketURL()
		u.RawQuery = canonicalQuery(params) // the signed query == the wire query

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("s3: list: %w", err)
		}
		req.URL = u
		c.sign(req, unsignedPayload)

		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("s3: list %q: %w", prefix, err)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxListPage))
		drainClose(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("s3: list %q: unexpected status %s: %s", prefix, resp.Status, snippet(body))
		}
		if rerr != nil {
			return nil, fmt.Errorf("s3: list %q: read body: %w", prefix, rerr)
		}

		var lr listBucketResult
		if err := xml.Unmarshal(body, &lr); err != nil {
			return nil, fmt.Errorf("s3: list %q: parse: %w", prefix, err)
		}
		for _, o := range lr.Contents {
			out = append(out, Object{Key: o.Key, Size: o.Size, LastModified: o.LastModified})
		}
		if lr.IsTruncated && lr.NextContinuationToken != "" {
			token = lr.NextContinuationToken
			continue
		}
		return out, nil
	}
}

// listBucketResult maps the ListObjectsV2 XML response. encoding/xml matches by local
// element name, so the S3 namespace on <ListBucketResult> is ignored.
type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"` // S3 emits RFC3339, which xml parses natively
	} `xml:"Contents"`
}

// sign stamps x-amz-date + x-amz-content-sha256, computes the SigV4 signature over the
// request, and sets the Authorization header. time.Now().UTC() is the correct clock
// source here: this is a live network client, and SigV4 requires the real wall-clock
// request time (skew beyond ~15m is rejected by S3).
func (c *Client) sign(req *http.Request, payloadHash string) {
	res := computeSigV4(
		req.Method,
		req.URL.EscapedPath(), // our RawPath: AWS-encoded, "/" separators kept
		req.URL.RawQuery,      // already canonical (built by canonicalQuery) or ""
		req.Header,
		req.URL.Host,
		payloadHash,
		c.cfg.AccessKeyID, c.cfg.SecretAccessKey, c.cfg.Region, serviceName,
		time.Now().UTC(),
	)
	auth := algorithm +
		" Credential=" + c.cfg.AccessKeyID + "/" + res.credentialScope +
		", SignedHeaders=" + res.signedHeaders +
		", Signature=" + res.signature
	req.Header.Set("Authorization", auth)
}

// objectURL builds the request URL for an object key. Path-style yields
// scheme://endpoint/bucket/key; virtual-host yields scheme://bucket.endpoint/key. The
// path is AWS-encoded into RawPath (keeping "/" separators) so the wire path is
// byte-identical to what we sign — Go's default path escaper would encode differently.
func (c *Client) objectURL(key string) *url.URL {
	var rawPath string
	if c.cfg.UsePathStyle {
		rawPath = "/" + c.cfg.Bucket + "/" + key
	} else {
		rawPath = "/" + key
	}
	return &url.URL{
		Scheme:  c.scheme(),
		Host:    c.host(),
		Path:    rawPath,
		RawPath: uriEncode(rawPath, false),
	}
}

// bucketURL builds the bucket-level URL used by List (path-style: /bucket; virtual-host: /).
func (c *Client) bucketURL() *url.URL {
	rawPath := "/"
	if c.cfg.UsePathStyle {
		rawPath = "/" + c.cfg.Bucket
	}
	return &url.URL{
		Scheme:  c.scheme(),
		Host:    c.host(),
		Path:    rawPath,
		RawPath: uriEncode(rawPath, false),
	}
}

func (c *Client) scheme() string {
	if c.cfg.Insecure {
		return "http"
	}
	return "https"
}

// host is the Host header / URL host we sign and send. Virtual-host style prepends the
// bucket label.
func (c *Client) host() string {
	if c.cfg.UsePathStyle {
		return c.cfg.Endpoint
	}
	return c.cfg.Bucket + "." + c.cfg.Endpoint
}

// responseError builds an error from a non-success response, including a bounded body
// snippet (S3 errors are small XML documents). The response body carries no secret.
func responseError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return fmt.Errorf("s3: %s: unexpected status %s: %s", op, resp.Status, snippet(body))
}

// snippet trims a body for safe inclusion in an error string.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	return s
}

// drainClose drains a bounded amount of the body then closes it, so the underlying
// connection can be reused (keep-alive) instead of being torn down.
func drainClose(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 64<<10))
	_ = rc.Close()
}
