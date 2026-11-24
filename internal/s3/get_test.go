package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" // testClient's secret key

func TestGetRequestShape(t *testing.T) {
	var got *http.Request
	payload := []byte("HMBK1\nencrypted-segment")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	c, host := testClient(t, ts)
	body, size, err := c.Get(context.Background(), "siem/v1/2026/11/22/14/web-1-0007.ndjson.gz.enc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, payload) || size != int64(len(payload)) {
		t.Errorf("body = %q size %d, want %q size %d", b, size, payload, len(payload))
	}
	if got.Method != http.MethodGet || got.URL.EscapedPath() != "/mybucket/siem/v1/2026/11/22/14/web-1-0007.ndjson.gz.enc" {
		t.Errorf("request = %s %s", got.Method, got.URL.EscapedPath())
	}
	assertSignedRequest(t, got, host)
	// The object must come back byte for byte: no transparent gzip negotiation.
	if ae := got.Header.Get("Accept-Encoding"); ae != "identity" {
		t.Errorf("Accept-Encoding = %q, want identity", ae)
	}
	if strings.Contains(got.Header.Get("Authorization"), "accept-encoding") {
		t.Errorf("accept-encoding must not be signed (proxies rewrite it): %q", got.Header.Get("Authorization"))
	}
}

func TestGetNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
	}))
	defer ts.Close()
	c, _ := testClient(t, ts)
	body, _, err := c.Get(context.Background(), "missing.enc")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(404) = %v, want ErrNotFound", err)
	}
	if body != nil {
		t.Error("a failed Get must not return a body")
	}
}

func TestGetErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code></Error>")
	}))
	defer ts.Close()
	c, _ := testClient(t, ts)
	_, _, err := c.Get(context.Background(), "k.enc")
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("Get(403) = %v, want a non-NotFound error carrying the S3 code", err)
	}
	if _, _, err := c.Get(context.Background(), ""); err == nil {
		t.Error("Get with an empty key must fail")
	}
}

// A server that answers with Content-Encoding: gzip must not get its body silently inflated:
// the archive object is compared byte for byte with its seal.
func TestGetNoTransparentGunzip(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("inflated"))
	_ = zw.Close()
	raw := gz.Bytes()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(raw)
	}))
	defer ts.Close()
	c, _ := testClient(t, ts)
	body, _, err := c.Get(context.Background(), "k.enc")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	b, _ := io.ReadAll(body)
	if !bytes.Equal(b, raw) {
		t.Errorf("Get inflated the body: got %q", b)
	}
}

// A hostile or broken endpoint may echo anything back; the client's error text must never carry
// the secret key or the access key id.
func TestErrorsNeverContainCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "<Error><Code>SignatureDoesNotMatch</Code><Echo>%s</Echo><Secret>%s</Secret></Error>",
			r.Header.Get("Authorization"), testSecret)
	}))
	defer ts.Close()
	c, _ := testClient(t, ts)
	ctx := context.Background()
	_, _, gerr := c.Get(ctx, "k")
	_, lerr := c.List(ctx, "p/")
	errs := map[string]error{
		"put":    c.Put(ctx, "k", strings.NewReader("x"), 1, ""),
		"get":    gerr,
		"list":   lerr,
		"delete": c.Delete(ctx, "k"),
	}
	for op, err := range errs {
		if err == nil {
			t.Errorf("%s: expected an error", op)
			continue
		}
		if s := err.Error(); strings.Contains(s, testSecret) || strings.Contains(s, "AKIDEXAMPLE") {
			t.Errorf("%s error leaks a credential: %s", op, s)
		}
		if !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
			t.Errorf("%s error lost the S3 code: %s", op, err)
		}
	}
}

// A credential that straddles the snippet's 512-byte cut is removed whole: scrubbing happens on
// the full body, before the cut.
func TestScrubBeforeSnippetCut(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, strings.Repeat("x", 508)+testSecret)
	}))
	defer ts.Close()
	c, _ := testClient(t, ts)
	_, _, gerr := c.Get(context.Background(), "k")
	_, lerr := c.List(context.Background(), "p/")
	for op, err := range map[string]error{"get": gerr, "list": lerr} {
		if err == nil || strings.Contains(err.Error(), testSecret[:4]) {
			t.Errorf("%s error keeps the start of the secret: %v", op, err)
		}
	}
}

func TestNewRejectsEndpointWithCredentialsOrPath(t *testing.T) {
	for _, ep := range []string{"AKID:secret@s3.example.com", "s3.example.com/sub", "s3.example.com?x=1", "s3.example.com#f", "s3 example.com"} {
		if _, err := New(Config{Endpoint: ep, Region: "r", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"}, nil); err == nil {
			t.Errorf("endpoint %q accepted", ep)
		} else if strings.Contains(err.Error(), "secret") && strings.Contains(ep, "secret") {
			t.Errorf("endpoint error echoes the userinfo: %v", err)
		}
	}
	if _, err := New(Config{Endpoint: "minio.internal:9000", Region: "r", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"}, nil); err != nil {
		t.Errorf("host:port rejected: %v", err)
	}
}

// A server that keeps saying "truncated" must not make List loop or grow forever.
func TestListBoundedAgainstEndlessPages(t *testing.T) {
	page := func(token string) string {
		return `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>` + token +
			`</NextContinuationToken><Contents><Key>a</Key><Size>1</Size></Contents></ListBucketResult>`
	}
	t.Run("same token", func(t *testing.T) {
		n := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n++
			_, _ = io.WriteString(w, page("SAME"))
		}))
		defer ts.Close()
		c, _ := testClient(t, ts)
		if _, err := c.List(context.Background(), ""); err == nil {
			t.Fatal("a repeated continuation token must fail")
		}
		if n > 3 {
			t.Errorf("made %d requests for a repeating token", n)
		}
	})
	t.Run("object cap", func(t *testing.T) {
		old := maxListObjects
		maxListObjects = 5
		defer func() { maxListObjects = old }()
		n := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n++
			_, _ = io.WriteString(w, page(fmt.Sprint("T", n)))
		}))
		defer ts.Close()
		c, _ := testClient(t, ts)
		if _, err := c.List(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Fatalf("List past the object cap = %v, want an error", err)
		}
		if n > 6 {
			t.Errorf("made %d requests past a 5-object cap", n)
		}
	})
	t.Run("endless tokens", func(t *testing.T) {
		old := maxListPages
		maxListPages = 50
		defer func() { maxListPages = old }()
		n := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n++
			_, _ = io.WriteString(w, page(fmt.Sprint("T", n)))
		}))
		defer ts.Close()
		c, _ := testClient(t, ts)
		if _, err := c.List(context.Background(), ""); err == nil {
			t.Fatal("endless pages must fail")
		}
		if n > maxListPages+1 {
			t.Errorf("made %d requests, cap is %d pages", n, maxListPages)
		}
	})
}
