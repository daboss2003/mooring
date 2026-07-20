package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestSigV4KnownAnswer pins the signer to the AWS-documented "Example: GET Object"
// vectors from the S3 SigV4 header-based-auth reference. If any step of the canonical
// request → string-to-sign → signing-key → signature chain regresses, the final
// signature diverges from the published value and this test fails.
//
//	https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
func TestSigV4KnownAnswer(t *testing.T) {
	// The example's fixed inputs.
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const (
		secret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		region    = "us-east-1"
		host      = "examplebucket.s3.amazonaws.com"
		emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256("")
	)

	hdr := http.Header{}
	hdr.Set("Range", "bytes=0-9") // the example signs a Range header

	res := computeSigV4(
		http.MethodGet, "/test.txt", "",
		hdr, host, emptyHash,
		"AKIAIOSFODNN7EXAMPLE", secret, region, serviceName, now,
	)

	// The signature is independent of the access key (it only names it in Credential),
	// so the exact access key does not affect this anchor value.
	const wantSig = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if res.signature != wantSig {
		t.Errorf("signature mismatch:\n got  %s\n want %s", res.signature, wantSig)
	}

	wantCanonical := strings.Join([]string{
		"GET",
		"/test.txt",
		"",
		"host:examplebucket.s3.amazonaws.com",
		"range:bytes=0-9",
		"x-amz-content-sha256:" + emptyHash,
		"x-amz-date:20130524T000000Z",
		"",
		"host;range;x-amz-content-sha256;x-amz-date",
		emptyHash,
	}, "\n")
	if res.canonicalRequest != wantCanonical {
		t.Errorf("canonical request mismatch:\n got:\n%s\n want:\n%s", res.canonicalRequest, wantCanonical)
	}

	wantSTS := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		"20130524T000000Z",
		"20130524/us-east-1/s3/aws4_request",
		"7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
	}, "\n")
	if res.stringToSign != wantSTS {
		t.Errorf("string-to-sign mismatch:\n got:\n%s\n want:\n%s", res.stringToSign, wantSTS)
	}

	if res.credentialScope != "20130524/us-east-1/s3/aws4_request" {
		t.Errorf("credential scope = %q", res.credentialScope)
	}
	if res.signedHeaders != "host;range;x-amz-content-sha256;x-amz-date" {
		t.Errorf("signed headers = %q", res.signedHeaders)
	}
}

// TestSigningKeyLadder checks the four-step HMAC derivation against the AWS-documented
// intermediate signing key for us-east-1/s3 on 2013-05-24 (final kSigning, hex).
func TestSigningKeyLadder(t *testing.T) {
	key := signingKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3")
	// Re-derive the example signature from a hand-built string-to-sign to confirm the
	// key is usable end to end (guards the ladder without hardcoding raw key bytes).
	sts := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n" +
		"7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
	got := hmacSHA256(key, sts)
	const wantSig = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if h := toHex(got); h != wantSig {
		t.Errorf("signing key ladder produced wrong signature:\n got  %s\n want %s", h, wantSig)
	}
}

func toHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

// TestURIEncode covers the AWS UriEncode rules and round-trips each encoding back to
// the original: spaces, unicode, slashes, "+", "~", and unreserved characters.
func TestURIEncode(t *testing.T) {
	cases := []struct {
		in        string
		wantPath  string // encodeSlash=false (object key paths)
		wantQuery string // encodeSlash=true (query strings)
	}{
		{"simple.txt", "simple.txt", "simple.txt"},
		{"a b.txt", "a%20b.txt", "a%20b.txt"},
		{"path/to/key", "path/to/key", "path%2Fto%2Fkey"},
		{"a+b=c", "a%2Bb%3Dc", "a%2Bb%3Dc"},
		{"keep-_.~", "keep-_.~", "keep-_.~"},
		{"café.txt", "caf%C3%A9.txt", "caf%C3%A9.txt"},
		{"100%done", "100%25done", "100%25done"},
		{"a&b?c#d", "a%26b%3Fc%23d", "a%26b%3Fc%23d"},
	}
	for _, tc := range cases {
		if got := uriEncode(tc.in, false); got != tc.wantPath {
			t.Errorf("uriEncode(%q, path) = %q, want %q", tc.in, got, tc.wantPath)
		}
		if got := uriEncode(tc.in, true); got != tc.wantQuery {
			t.Errorf("uriEncode(%q, query) = %q, want %q", tc.in, got, tc.wantQuery)
		}
		// Round-trip: the query encoding (which escapes "/") must decode back exactly.
		dec, err := url.PathUnescape(uriEncode(tc.in, true))
		if err != nil || dec != tc.in {
			t.Errorf("round-trip of %q failed: dec=%q err=%v", tc.in, dec, err)
		}
	}
}

func TestCanonicalQuerySortedAndEncoded(t *testing.T) {
	got := canonicalQuery([][2]string{
		{"prefix", "backups/app/"},
		{"list-type", "2"},
		{"continuation-token", "a+b/c=="},
	})
	want := "continuation-token=a%2Bb%2Fc%3D%3D&list-type=2&prefix=backups%2Fapp%2F"
	if got != want {
		t.Errorf("canonicalQuery:\n got  %s\n want %s", got, want)
	}
}

// --- httptest-backed request-shape tests --------------------------------------

func testClient(t *testing.T, ts *httptest.Server) (*Client, string) {
	t.Helper()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		Endpoint:        u.Host,
		Region:          "us-east-1",
		Bucket:          "mybucket",
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		UsePathStyle:    true,
		Insecure:        true,
	}, ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c, u.Host
}

func assertSignedRequest(t *testing.T, r *http.Request, wantHost string) {
	t.Helper()
	if r.Host != wantHost {
		t.Errorf("Host = %q, want %q", r.Host, wantHost)
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") {
		t.Errorf("Authorization not well-formed: %q", auth)
	}
	if !strings.Contains(auth, "Signature=") || !strings.Contains(auth, "SignedHeaders=") {
		t.Errorf("Authorization missing signature/signed-headers: %q", auth)
	}
	// host, x-amz-date and x-amz-content-sha256 must always be signed (order-independent).
	for _, h := range []string{"host", "x-amz-content-sha256", "x-amz-date"} {
		if !strings.Contains(auth, h) {
			t.Errorf("signed headers missing %q: %q", h, auth)
		}
	}
	if r.Header.Get("X-Amz-Content-Sha256") != "UNSIGNED-PAYLOAD" {
		t.Errorf("x-amz-content-sha256 = %q, want UNSIGNED-PAYLOAD", r.Header.Get("X-Amz-Content-Sha256"))
	}
	if m := regexp.MustCompile(`^\d{8}T\d{6}Z$`); !m.MatchString(r.Header.Get("X-Amz-Date")) {
		t.Errorf("x-amz-date malformed: %q", r.Header.Get("X-Amz-Date"))
	}
}

func TestPutRequestShape(t *testing.T) {
	var got *http.Request
	var body []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		got = r
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, host := testClient(t, ts)
	payload := []byte("encrypted-backup-blob")
	err := c.Put(context.Background(), "backups/app/2026-07-20.enc",
		bytes.NewReader(payload), int64(len(payload)), "application/octet-stream")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got.Method != http.MethodPut {
		t.Errorf("method = %s", got.Method)
	}
	if got.URL.EscapedPath() != "/mybucket/backups/app/2026-07-20.enc" {
		t.Errorf("path = %q", got.URL.EscapedPath())
	}
	if got.Header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("content-type = %q", got.Header.Get("Content-Type"))
	}
	if !bytes.Equal(body, payload) {
		t.Errorf("body = %q, want %q", body, payload)
	}
	// content-type is a controlled header, so it must be in the signed set.
	if !strings.Contains(got.Header.Get("Authorization"), "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") {
		t.Errorf("signed headers wrong: %q", got.Header.Get("Authorization"))
	}
	assertSignedRequest(t, got, host)
}

func TestPutKeyWithSpaceIsEncoded(t *testing.T) {
	var got *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c, _ := testClient(t, ts)
	if err := c.Put(context.Background(), "my backups/a b.enc", strings.NewReader("x"), 1, ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Wire path must be percent-encoded (space -> %20), slashes preserved.
	if got.URL.EscapedPath() != "/mybucket/my%20backups/a%20b.enc" {
		t.Errorf("escaped path = %q", got.URL.EscapedPath())
	}
	// And it must decode back to the original key on the server side.
	if got.URL.Path != "/mybucket/my backups/a b.enc" {
		t.Errorf("decoded path = %q", got.URL.Path)
	}
}

func TestDeleteRequestShapeAndIdempotency(t *testing.T) {
	// 204 success.
	var got *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.WriteHeader(http.StatusNoContent)
	}))
	c, host := testClient(t, ts)
	if err := c.Delete(context.Background(), "backups/old.enc"); err != nil {
		t.Fatalf("Delete(204): %v", err)
	}
	if got.Method != http.MethodDelete || got.URL.EscapedPath() != "/mybucket/backups/old.enc" {
		t.Errorf("delete request wrong: %s %s", got.Method, got.URL.EscapedPath())
	}
	assertSignedRequest(t, got, host)
	ts.Close()

	// 404 must be treated as already-deleted (idempotent).
	ts404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts404.Close()
	c2, _ := testClient(t, ts404)
	if err := c2.Delete(context.Background(), "backups/missing.enc"); err != nil {
		t.Errorf("Delete(404) should be nil, got %v", err)
	}
}

func TestListPaginates(t *testing.T) {
	page1 := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>mybucket</Name>
  <Prefix>backups/</Prefix>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>TOKEN/PAGE+2==</NextContinuationToken>
  <Contents><Key>backups/a.enc</Key><LastModified>2026-07-19T10:00:00.000Z</LastModified><Size>1024</Size></Contents>
</ListBucketResult>`
	page2 := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>mybucket</Name>
  <Prefix>backups/</Prefix>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>backups/b.enc</Key><LastModified>2026-07-20T11:30:00.000Z</LastModified><Size>2048</Size></Contents>
</ListBucketResult>`

	var reqs []*http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r)
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("continuation-token") == "" {
			_, _ = io.WriteString(w, page1)
		} else {
			_, _ = io.WriteString(w, page2)
		}
	}))
	defer ts.Close()

	c, host := testClient(t, ts)
	objs, err := c.List(context.Background(), "backups/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("got %d objects, want 2: %+v", len(objs), objs)
	}
	if objs[0].Key != "backups/a.enc" || objs[0].Size != 1024 {
		t.Errorf("obj0 = %+v", objs[0])
	}
	if objs[1].Key != "backups/b.enc" || objs[1].Size != 2048 {
		t.Errorf("obj1 = %+v", objs[1])
	}
	if !objs[0].LastModified.Equal(time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("obj0 LastModified = %v", objs[0].LastModified)
	}

	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests (pagination), got %d", len(reqs))
	}
	// Page 1 request shape.
	q0 := reqs[0].URL.Query()
	if reqs[0].Method != http.MethodGet || reqs[0].URL.EscapedPath() != "/mybucket" {
		t.Errorf("list req0 = %s %s", reqs[0].Method, reqs[0].URL.EscapedPath())
	}
	if q0.Get("list-type") != "2" || q0.Get("prefix") != "backups/" {
		t.Errorf("list req0 query = %v", q0)
	}
	assertSignedRequest(t, reqs[0], host)
	// Page 2 must carry the continuation token (decoded back to the original value).
	if reqs[1].URL.Query().Get("continuation-token") != "TOKEN/PAGE+2==" {
		t.Errorf("continuation-token = %q", reqs[1].URL.Query().Get("continuation-token"))
	}
}

func TestNewValidatesConfig(t *testing.T) {
	bad := []Config{
		{Region: "us-east-1", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"}, // no endpoint
		{Endpoint: "e", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"},        // no region
		{Endpoint: "e", Region: "r", AccessKeyID: "a", SecretAccessKey: "s"},        // no bucket
		{Endpoint: "e", Region: "r", Bucket: "b", SecretAccessKey: "s"},             // no access key
		{Endpoint: "e", Region: "r", Bucket: "b", AccessKeyID: "a"},                 // no secret
	}
	for i, cfg := range bad {
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	// A scheme-prefixed endpoint is normalized rather than rejected.
	c, err := New(Config{Endpoint: "https://s3.example.com/", Region: "r", Bucket: "b", AccessKeyID: "a", SecretAccessKey: "s"}, nil)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.cfg.Endpoint != "s3.example.com" {
		t.Errorf("endpoint not normalized: %q", c.cfg.Endpoint)
	}
}
