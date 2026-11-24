// Package redact removes secrets from security-log events and turns personal data into keyed
// hashes or drops it (docs/security-logs.md "Redaction").
package redact

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/daboss2003/mooring/internal/siem"
)

// Options adjusts the built-in personal-data lists (config security_logs.pii). Names match a
// field's last dotted element, case-insensitively.
type Options struct {
	HashFields []string // stored as a keyed hash
	DropFields []string // removed
	KeepFields []string // taken out of the built-in lists
}

// Redactor applies redaction. Safe for concurrent use.
type Redactor struct {
	key []byte
	opt Options

	exact  map[string]class  // normalized name → class, every list merged by precedence
	suffix [256][]suffixRule // by last byte; tried in order when exact has no entry
	macs   sync.Pool         // *hasher
}

type hasher struct {
	mac hash.Hash
	buf []byte
	sum []byte
}

const redacted = "[redacted]"

// class is what happens to a field (or a key=value pair in text) with a given name.
type class uint8

const (
	clsNone      class = iota
	clsKeep            // in KeepFields: no personal-data rule applies (secrets still do)
	clsSecret          // value → [redacted]
	clsHeader          // a secret whose unquoted value in text runs to the end of the line
	clsSignature       // a secret only when the value is a long base64/hex string
	clsHash            // value → Hash(value)
	clsDrop            // field removed (in text: value → [redacted])
)

type suffixRule struct {
	s []byte
	c class
}

// Built-in names, in normalized form (lowercase, '_' and '-' removed).
var (
	secretNames = []string{"password", "passwd", "pwd", "pass", "passphrase", "secret", "clientsecret",
		"token", "accesstoken", "refreshtoken", "idtoken", "apikey", "apisecret", "xapikey",
		"session", "sessionid", "sessiontoken", "jwt", "otp", "totp", "otpcode", "pin", "cvv", "cvc",
		"cardnumber", "pan", "privatekey", "credentials"}
	headerNames = []string{"authorization", "proxyauthorization", "cookie", "cookies", "setcookie"}
	// A longer name ending in one of these is a secret too (db_password, X-Amz-Security-Token,
	// AWS_SECRET_ACCESS_KEY).
	secretSuffixes = []string{"password", "passwd", "passphrase", "secret", "token", "apikey",
		"privatekey", "secretkey", "accesskey", "signingkey", "encryptionkey", "masterkey",
		"credentials", "sessionid"}
	headerSuffixes = []string{"authorization", "cookie"}

	hashNames = []string{"imei", "imei1", "imei2", "meid", "serial", "serialnumber", "deviceid",
		"androidid", "udid", "email", "emailaddress", "phone", "phonenumber", "msisdn", "account"}
	// A longer name ending in one of these is personal data too (user_email, contact_phone).
	hashSuffixes = []string{"email", "emailaddress", "phone", "phonenumber", "mobilenumber", "msisdn",
		"imei", "deviceid", "androidid", "serialnumber", "account", "accountnumber"}

	dropNames = []string{"lat", "lon", "lng", "latitude", "longitude", "coords", "coordinates", "gps",
		"location", "altitude"}
	dropSuffixes = []string{"latitude", "longitude", "coords", "coordinates", "gps", "location", "altitude"}
)

// New builds a Redactor; key is siem.DeriveKey(master, siem.KeyPII) (32 bytes).
func New(key []byte, opt Options) (*Redactor, error) {
	if len(key) < 32 {
		return nil, errors.New("redact: key must be at least 32 bytes")
	}
	k := append([]byte(nil), key...)
	r := &Redactor{key: k, opt: opt, exact: map[string]class{}}
	r.macs.New = func() any { return &hasher{mac: hmac.New(sha256.New, k)} }

	keep := normSet(opt.KeepFields)
	// Lowest precedence first; a later list overwrites: secrets > DropFields > HashFields >
	// KeepFields > built-in drop > built-in hash.
	for _, n := range hashNames {
		r.exact[n] = clsHash
	}
	for _, n := range dropNames {
		r.exact[n] = clsDrop
	}
	for n := range keep {
		r.exact[n] = clsKeep
	}
	for n := range normSet(opt.HashFields) {
		r.exact[n] = clsHash
	}
	for n := range normSet(opt.DropFields) {
		r.exact[n] = clsDrop
	}
	for _, n := range secretNames {
		r.exact[n] = clsSecret
	}
	for _, n := range headerNames {
		r.exact[n] = clsHeader
	}
	r.exact["signature"] = clsSignature

	add := func(list []string, c class, skipKept bool) {
		for _, s := range list {
			if skipKept && keep[s] {
				continue
			}
			last := s[len(s)-1]
			r.suffix[last] = append(r.suffix[last], suffixRule{[]byte(s), c})
		}
	}
	add(headerSuffixes, clsHeader, false)
	add(secretSuffixes, clsSecret, false)
	add([]string{"signature"}, clsSignature, false)
	add(dropSuffixes, clsDrop, true)
	add(hashSuffixes, clsHash, true)
	return r, nil
}

func normSet(names []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		var buf [maxName]byte
		if b, whole := normName(&buf, strings.TrimSpace(n)); whole && len(b) > 0 {
			m[string(b)] = true
		}
	}
	return m
}

// Apply redacts e in place: secret values are replaced in F, Msg and URL query values; personal
// data fields are hashed (Hash) or dropped; Actor is hashed when it is personal data (an email).
func (r *Redactor) Apply(e *siem.Event) {
	if e == nil {
		return
	}
	var rename []string
	for k, v := range e.F {
		if len(k) >= 16 && hasToken(k) {
			delete(e.F, k) // a map keyed by a credential would store it as a key
			continue
		}
		c := r.classify(k)
		if c == clsDrop {
			delete(e.F, k)
			continue
		}
		if keyMayHoldPII(k) {
			rename = append(rename, k)
		}
		switch tv := v.(type) {
		case string:
			if t, _ := r.stored(c, tv); t != tv {
				e.F[k] = t
			}
		case float64:
			// Owner decision: a number of a secret field is redacted (otp.code, pin) unless its own
			// name is a measure and not itself a secret name (session.duration_ms, token.expires_in).
			if (c == clsSecret || c == clsHeader) && (r.leafSecret(k) || !measureLeaf(k)) {
				e.F[k] = redacted
			} else if c == clsHash {
				e.F[k] = r.Hash(strconv.FormatFloat(tv, 'f', -1, 64))
			}
		case bool:
			// Owner decision: a boolean is never redacted or hashed (has_password: true); it can't
			// carry a secret.
		}
	}
	if rename != nil {
		// Sorted so that two names hashing to the same new name resolve the same way each time.
		sort.Strings(rename)
		for _, k := range rename {
			if nk := r.hashKey(k); nk != k {
				v := e.F[k]
				delete(e.F, k)
				// The new name is checked as the old one was: decoding an element can bare a
				// credential (%22AKIA…%22).
				if _, dup := e.F[nk]; !dup && !(len(nk) >= 16 && hasToken(nk)) {
					e.F[nk] = v
				}
			}
		}
	}
	e.Msg = r.text(e.Msg, true)
	e.Actor = r.actor(e.Actor)
}

// keyMayHoldPII is the cheap check before hashKey: an '@' or %40 (an address), or a '+' or '0'
// followed by digits (a phone number).
func keyMayHoldPII(k string) bool {
	if strings.IndexByte(k, '@') >= 0 || strings.Contains(k, "%40") {
		return true
	}
	for i := 0; i+1 < len(k); i++ {
		if (k[i] == '+' || k[i] == '0') && k[i+1] >= '0' && k[i+1] <= '9' {
			return true
		}
	}
	return false
}

// hashKey returns field name k with each element that is an email address or a phone number replaced
// by its Hash ({"attempts":{"victim@x.com":3}} → attempts.h:…), the rest of the name kept. parse
// writes the dots of an address key as %2E, so the address is one element. An address still
// spanning elements (a dotted name from elsewhere) is hashed whole, never kept in clear.
func (r *Redactor) hashKey(k string) string {
	var b strings.Builder
	changed := false
	for i, el := range strings.Split(k, ".") {
		if i > 0 {
			b.WriteByte('.')
		}
		d := el
		if strings.IndexByte(el, '%') >= 0 {
			d = pctDecode(el)
		}
		var h string
		if t := strings.TrimSpace(d); isEmail(t) || phoneToken(t) {
			h = r.Hash(t)
		} else if h = r.phones(r.emails(d)); h != d {
			// An address or number inside a longer element (login:victim@x.com, <victim@x.com>):
			// hashed in place, the element re-escaped as parse wrote it.
			h = strings.ReplaceAll(strings.ReplaceAll(h, "%", "%25"), ".", "%2E")
		} else {
			b.WriteString(el)
			continue
		}
		b.WriteString(h)
		changed = true
	}
	out := k
	if changed {
		out = b.String()
	}
	if strings.IndexByte(out, '@') >= 0 || strings.Contains(out, "%40") {
		out = r.emails(out)
	}
	return out
}

// stored is what Apply keeps for the string value s of a field of class c; keep is false when
// the field is removed. Apply and SearchValue both use it, so a search value is always the
// stored form.
func (r *Redactor) stored(c class, s string) (v string, keep bool) {
	switch c {
	case clsDrop:
		return "", false
	case clsSecret, clsHeader:
		if s == "" {
			return s, true // an empty value has nothing to hide
		}
		return redacted, true
	case clsSignature:
		if longToken(s) {
			return redacted, true
		}
	case clsHash:
		if s == "" {
			return s, true
		}
		return r.Hash(s), true
	case clsKeep:
		return r.text(s, false), true
	}
	return r.text(s, true), true
}

// SearchText returns free search text the way Apply stores text: every email address and phone
// number in it replaced by its hash (so a search for one matches, and an audit row of the search
// doesn't keep it in clear). It is exactly what Apply stores for the same text in Msg, so a
// secret in it is [redacted] too; everything else is unchanged.
func (r *Redactor) SearchText(text string) string { return r.text(text, true) }

// SecretField reports whether field (an F key, as typed after "f." in a search, or "actor") is
// stored as a secret, i.e. its value is replaced by [redacted], under the same element rules
// Apply uses. A signature field counts: its long values are redacted.
func (r *Redactor) SecretField(field string) bool {
	if strings.EqualFold(strings.TrimSpace(field), "actor") {
		return false
	}
	switch r.classify(field) {
	case clsSecret, clsHeader, clsSignature:
		return true
	}
	return false
}

// SearchValue returns value the way Apply would store it in field ("actor", or an F key's last
// dotted element): hashed when that field/value would be hashed (e.g. an actor that looks like an
// email or phone number, any hash-list field), unchanged otherwise; already-hashed input is
// returned as is. A secret or dropped field's value is returned unchanged.
func (r *Redactor) SearchValue(field, value string) string {
	var s string
	if strings.EqualFold(strings.TrimSpace(field), "actor") {
		s = r.actor(value)
	} else {
		var keep bool
		if s, keep = r.stored(r.classify(field), value); !keep {
			return value
		}
	}
	// Intentional: a secret is never stored, so its input comes back as is and matches nothing:
	// a search can't confirm a guessed secret, nor match every [redacted] marker.
	if s == redacted && value != redacted {
		return value
	}
	return s
}

func (r *Redactor) actor(a string) string {
	if a == "" || isHash(a) {
		return a
	}
	if t := strings.TrimSpace(a); isEmail(t) || isPhone(t) {
		return r.Hash(t)
	}
	return r.text(a, true)
}

// Hash is the keyed hash stored for a personal-data value: "h:" + 16 lowercase hex characters.
// The same value always gives the same hash, so it can still be searched and matched.
func (r *Redactor) Hash(v string) string {
	v = strings.TrimSpace(v)
	if isHash(v) {
		return v
	}
	if strings.IndexByte(v, '@') > 0 {
		v = strings.ToLower(v)
	}
	h := r.macs.Get().(*hasher)
	h.mac.Reset()
	h.buf = append(h.buf[:0], v...)
	h.mac.Write(h.buf)
	h.sum = h.mac.Sum(h.sum[:0])
	var out [18]byte
	out[0], out[1] = 'h', ':'
	hex.Encode(out[2:], h.sum[:8])
	if cap(h.buf) <= 16<<10 {
		r.macs.Put(h)
	}
	return string(out[:])
}

// Hashed reports whether a field (its last dotted element; "actor" for Event.Actor) is stored
// hashed, so a search for it must hash the value first.
func (r *Redactor) Hashed(field string) bool {
	var buf [maxName]byte
	if b, whole := normName(&buf, field); whole && string(b) == "actor" {
		return true
	}
	return r.classify(field) == clsHash
}

// isHash reports whether v is already a Hash result.
func isHash(v string) bool {
	if len(v) != 18 || v[0] != 'h' || v[1] != ':' {
		return false
	}
	for i := 2; i < 18; i++ {
		if c := v[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// maxName bounds a normalized name; longer names keep their tail (enough for the suffix rules)
// but can't match a name exactly.
const maxName = 64

// normName writes name's last element (after the last '.' or '['; ']' removed), lowercased with
// '_' and '-' removed, into buf and returns it. whole is false when the element was longer than
// buf and only its tail is returned.
func normName[T ~string | ~[]byte](buf *[maxName]byte, name T) (b []byte, whole bool) {
	end := len(name)
	for end > 0 && name[end-1] == ']' {
		end--
	}
	n := 0
	i := end - 1
	for ; i >= 0; i-- {
		c := name[i]
		if c == '.' || c == '[' {
			break
		}
		if c == '_' || c == '-' || c == ']' {
			continue
		}
		if n == maxName {
			return buf[:], false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		n++
		buf[maxName-n] = c
	}
	return buf[maxName-n:], true
}

// pctDecode decodes %XX escapes and leaves anything malformed as it is.
func pctDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pctDecodeTo appends s with %XX escapes decoded to dst.
func pctDecodeTo(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			dst = append(dst, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		dst = append(dst, s[i])
	}
	return dst
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// classify returns what happens to a field (or a key in text) called name. Every element of the
// name counts, so a parent passes its class on (owner decision): password.new, session.id and
// cookies.connect.sid are secrets; phone.number and account.id are hashed; location.city is
// dropped. A secret element anywhere wins, then a dropped one, then a hashed one. An element in
// KeepFields only stops its own match. Empty and numeric elements (password[], token[0]) are
// skipped, so the element before the brackets decides.
func (r *Redactor) classify(name string) class {
	if strings.IndexByte(name, '%') < 0 {
		return classifyName(r, name)
	}
	// Decoded on the stack: names in text are at most maxKeyScan bytes, and this runs at every
	// separator of a line.
	var buf [2 * maxKeyScan]byte
	if len(name) <= len(buf) {
		return classifyName(r, pctDecodeTo(buf[:0], name))
	}
	return classifyName(r, pctDecode(name))
}

func classifyName[T ~string | ~[]byte](r *Redactor, name T) class {
	best, sig, first := clsNone, false, true
	for end := len(name); end > 0; {
		start := end
		for start > 0 && name[start-1] != '.' && name[start-1] != '[' {
			start--
		}
		c, ok := element(r, name[start:end])
		end = start - 1
		if !ok {
			continue
		}
		switch c {
		case clsHeader:
			if first {
				return clsHeader // its unquoted value in text runs to the end of the line
			}
			return clsSecret
		case clsSecret:
			return clsSecret
		case clsSignature:
			sig = true
		case clsDrop:
			best = clsDrop
		case clsHash:
			if best != clsDrop {
				best = clsHash
			}
		case clsKeep:
			if best == clsNone {
				best = clsKeep
			}
		}
		first = false
	}
	if sig && best != clsDrop && best != clsHash {
		return clsSignature
	}
	return best
}

// classifyText is classify for a key found in text: only its last element counts (user.password,
// password[], token[0]). Intentional: in a line, dots before ':' or '=' are mostly a host name
// (session.example.com:8443, account.example.com:443), not a nested key; inheritance is for F
// keys, whose dots are structure.
func (r *Redactor) classifyText(name string) class {
	if strings.IndexByte(name, '%') < 0 {
		return lastElement(r, name)
	}
	var buf [2 * maxKeyScan]byte
	if len(name) <= len(buf) {
		return lastElement(r, pctDecodeTo(buf[:0], name))
	}
	return lastElement(r, pctDecode(name))
}

func lastElement[T ~string | ~[]byte](r *Redactor, name T) class {
	for end := len(name); end > 0; {
		start := end
		for start > 0 && name[start-1] != '.' && name[start-1] != '[' {
			start--
		}
		if c, ok := element(r, name[start:end]); ok {
			return c
		}
		end = start - 1
	}
	return clsNone
}

// Measures: the names of a number or bool that is a measure, not a secret, under a secret parent
// (session.duration_ms, token.expires_in, otp.attempts, cookie.secure). Exact names, then suffixes
// (*_ms, *_at, *_count, …). Intentional: "pass" counts too (checks.pass: 12 is a count of passed
// checks), so a numeric top-level "pass" stays readable; a password is a string.
var (
	measureNames = map[string]bool{"duration": true, "elapsed": true, "latency": true, "ttl": true,
		"maxage": true, "expires": true, "expiresin": true, "expiry": true, "exp": true, "iat": true,
		"nbf": true, "age": true, "count": true, "total": true, "attempts": true, "retries": true,
		"tries": true, "size": true, "length": true, "len": true, "bytes": true, "status": true,
		"statuscode": true, "ok": true, "valid": true, "verified": true, "enabled": true, "expired": true,
		"secure": true, "httponly": true, "success": true, "succeeded": true, "failed": true, "pass": true,
		"passed": true, "fail": true, "failures": true, "limit": true, "remaining": true, "version": true,
		"index": true, "idx": true}
	measureSuffixes = []string{"ms", "millis", "seconds", "secs", "at", "count", "size", "length", "ttl",
		"duration", "attempts", "total", "bytes"}
)

// leafSecret reports whether the last element of field name k (skipping empty and numeric ones) is
// itself a secret or header name. Intentional: such a field is redacted even when that name is also
// a measure ("pass"), because its value may be the secret itself (a numeric PIN).
func (r *Redactor) leafSecret(k string) bool {
	for end := len(k); end > 0; {
		start := end
		for start > 0 && k[start-1] != '.' && k[start-1] != '[' {
			start--
		}
		c, ok := element(r, k[start:end])
		end = start - 1
		if !ok {
			continue
		}
		return c == clsSecret || c == clsHeader
	}
	return false
}

// measureLeaf reports whether the last element of field name k is a measure name.
func measureLeaf(k string) bool {
	for end := len(k); end > 0; {
		start := end
		for start > 0 && k[start-1] != '.' && k[start-1] != '[' {
			start--
		}
		var buf [maxName]byte
		b, whole := normName(&buf, k[start:end])
		end = start - 1
		if len(b) == 0 || allDigits(b) {
			continue
		}
		if whole && measureNames[string(b)] {
			return true
		}
		for _, sfx := range measureSuffixes {
			if bytes.HasSuffix(b, []byte(sfx)) {
				return true
			}
		}
		return false
	}
	return false
}

// element classifies one element of a name; ok is false for an empty or numeric one.
func element[T ~string | ~[]byte](r *Redactor, el T) (class, bool) {
	var buf [maxName]byte
	b, whole := normName(&buf, el)
	if len(b) == 0 || allDigits(b) {
		return clsNone, false
	}
	if whole {
		if c, ok := r.exact[string(b)]; ok {
			return c, true
		}
	}
	for _, s := range r.suffix[b[len(b)-1]] {
		if bytes.HasSuffix(b, s.s) {
			return s.c, true
		}
	}
	return clsNone, true
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// longToken reports whether s looks like a signature: 32+ characters of base64/base64url/hex.
func longToken(s string) bool {
	if len(s) < 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '+' || c == '/' || c == '=' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// isPhone reports whether s looks like a phone number: "+" and 7–15 digits, or 10–15 digits
// without it, with optional spaces, dots, dashes and parentheses. Intentional: a bare 10-digit
// number also matches, which covers a bank account number (NUBAN) used as an actor.
func isPhone(s string) bool {
	if s == "" {
		return false
	}
	plus := s[0] == '+'
	if plus {
		s = s[1:]
	}
	digits := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == ' ' || c == '-' || c == '.' || c == '(' || c == ')':
			if digits == 0 && c != '(' {
				return false
			}
		default:
			return false
		}
	}
	if plus {
		return digits >= 7 && digits <= 15
	}
	return digits >= 10 && digits <= 15
}
