package s3

// sign.go implements AWS Signature Version 4 (SigV4) request signing from the
// standard library only — no AWS SDK, no third-party crypto. Every step below maps
// 1:1 to the AWS reference procedure so the KNOWN-ANSWER test in s3_test.go pins us
// to the AWS-documented example vectors and catches any regression:
//
//	https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
//	https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
//
// The chain is: build the CANONICAL REQUEST → hash it into the STRING-TO-SIGN →
// derive the per-request SIGNING KEY via the four-step HMAC ladder → HMAC the
// string-to-sign with that key → assemble the Authorization header. The secret key
// and the derived Authorization header are NEVER logged (this package logs nothing).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// algorithm is the fixed SigV4 algorithm token.
	algorithm = "AWS4-HMAC-SHA256"
	// serviceName is "s3" — it feeds the credential scope and the signing key.
	serviceName = "s3"
	// unsignedPayload lets us sign a request without hashing (and therefore without
	// buffering) the body. Valid over TLS; the same literal goes into both the
	// canonical request's hashed-payload slot and the x-amz-content-sha256 header.
	unsignedPayload = "UNSIGNED-PAYLOAD"
	// iso8601Basic is the x-amz-date layout: YYYYMMDD'T'HHMMSS'Z', UTC.
	iso8601Basic = "20060102T150405Z"
	// dateStampFmt is the YYYYMMDD credential-scope date.
	dateStampFmt = "20060102"
)

// sigV4Result carries the intermediate SigV4 products so the known-answer test can
// assert against the AWS-documented canonical request / string-to-sign / signature,
// not just the final header.
type sigV4Result struct {
	canonicalRequest string
	stringToSign     string
	signature        string
	signedHeaders    string // e.g. "host;x-amz-content-sha256;x-amz-date"
	credentialScope  string // e.g. "20130524/us-east-1/s3/aws4_request"
}

// computeSigV4 performs the full SigV4 computation. It is deliberately pure and
// side-effect-light so it is unit-testable with an injected fixed time and host:
// the only mutation is stamping x-amz-date and x-amz-content-sha256 into hdr, which
// MUST be signed and MUST also be sent on the wire.
//
//   - canonicalURI  — the already-URI-encoded path (see uriEncode; "/" kept unencoded)
//   - canonicalQuery — the already-encoded, sorted query string ("" when none)
//   - host          — the value of the Host header exactly as it will be sent
//   - payloadHash   — hex(SHA256(body)) or the literal "UNSIGNED-PAYLOAD"
func computeSigV4(method, canonicalURI, canonicalQuery string, hdr http.Header, host, payloadHash, accessKey, secret, region, service string, now time.Time) sigV4Result {
	amzDate := now.UTC().Format(iso8601Basic)
	dateStamp := now.UTC().Format(dateStampFmt)

	// These two headers are part of the signature, so set them before canonicalizing.
	hdr.Set("X-Amz-Date", amzDate)
	hdr.Set("X-Amz-Content-Sha256", payloadHash)

	// 1. Canonical request.
	canonHeaders, signedHeaders := canonicalHeaders(hdr, host)
	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonHeaders, // already ends in "\n"; the Join newline below yields the blank line
		signedHeaders,
		payloadHash,
	}, "\n")

	// 2. String to sign (hash of the canonical request + scope metadata).
	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")

	// 3. Derive the signing key and 4. sign.
	key := signingKey(secret, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	return sigV4Result{
		canonicalRequest: canonicalRequest,
		stringToSign:     stringToSign,
		signature:        signature,
		signedHeaders:    signedHeaders,
		credentialScope:  scope,
	}
}

// canonicalHeaders builds the CanonicalHeaders block (each "name:value\n", lowercased
// names, sorted) and the SignedHeaders list (";"-joined). host is always signed; every
// header currently present on hdr is signed too — for our requests that is exactly the
// controlled set (content-type, x-amz-date, x-amz-content-sha256), never Go's later
// transport-added headers (User-Agent, Accept-Encoding) which stay unsigned and are
// ignored by S3.
func canonicalHeaders(hdr http.Header, host string) (canonical string, signed string) {
	values := map[string]string{"host": host}
	names := []string{"host"}
	for name, vals := range hdr {
		lname := strings.ToLower(name)
		if _, seen := values[lname]; !seen && lname != "host" {
			names = append(names, lname)
		}
		values[lname] = canonicalHeaderValue(vals)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// canonicalHeaderValue trims each value, collapses internal runs of spaces to one,
// and comma-joins multiple values — matching the AWS Trimall rule for unquoted values.
func canonicalHeaderValue(vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = collapseSpaces(strings.TrimSpace(v))
	}
	return strings.Join(parts, ",")
}

// collapseSpaces reduces runs of ASCII spaces to a single space.
func collapseSpaces(s string) string {
	if !strings.Contains(s, "  ") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// uriEncode implements the AWS UriEncode function. It URI-encodes s byte-by-byte
// (so multi-byte UTF-8 becomes multiple %XX octets); unreserved characters
// A-Z a-z 0-9 - _ . ~ pass through; every other byte becomes uppercase %XX. When
// encodeSlash is false, "/" is preserved — used for object-key PATHS so the segment
// separators survive. When true (query strings), "/" is encoded as %2F. Space always
// becomes %20 (space is not unreserved), "+" becomes %2B.
func uriEncode(s string, encodeSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isUnreserved(c):
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}

// isUnreserved reports whether c is an RFC 3986 unreserved character, which SigV4
// leaves un-percent-encoded.
func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '~':
		return true
	default:
		return false
	}
}

// canonicalQuery encodes and sorts query parameters into the canonical query string:
// each name and value is URI-encoded (encodeSlash=true), pairs are sorted by encoded
// name then encoded value, and joined name=value with "&".
func canonicalQuery(params [][2]string) string {
	encoded := make([][2]string, len(params))
	for i, p := range params {
		encoded[i] = [2]string{uriEncode(p[0], true), uriEncode(p[1], true)}
	}
	sort.Slice(encoded, func(i, j int) bool {
		if encoded[i][0] != encoded[j][0] {
			return encoded[i][0] < encoded[j][0]
		}
		return encoded[i][1] < encoded[j][1]
	})
	pairs := make([]string, len(encoded))
	for i, p := range encoded {
		pairs[i] = p[0] + "=" + p[1]
	}
	return strings.Join(pairs, "&")
}

// signingKey derives the per-request key via the four-step HMAC ladder:
// kDate = HMAC("AWS4"+secret, date); kRegion = HMAC(kDate, region);
// kService = HMAC(kRegion, service); kSigning = HMAC(kService, "aws4_request").
func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
