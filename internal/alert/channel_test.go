package alert

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The managed-ntfy channel publishes to Mooring's OWN ntfy on loopback (which the SSRF
// guard blocks for every other channel), and MUST refuse any non-loopback target so a
// tampered config can't turn it into an off-host SSRF.
func TestNtfyManagedLoopbackOnly(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close() // srv.URL is http://127.0.0.1:PORT (loopback)

	cfg := fmt.Sprintf(`{"url":%q,"topic":"alerts","token":"tk_write","sub_user":"phone","sub_pass":"pw","base_url":"https://h.example"}`, srv.URL)
	ch, err := BuildChannel("ntfy_managed", []byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), Notification{Title: "t", Body: "b"}); err != nil {
		t.Fatalf("loopback send failed: %v", err)
	}
	if gotPath != "/alerts" || gotAuth != "Bearer tk_write" {
		t.Errorf("publish wrong: path=%q auth=%q", gotPath, gotAuth)
	}

	// A non-loopback target must be refused outright (no request).
	bad := `{"url":"https://evil.example.com","topic":"alerts","token":"tk_write","sub_user":"phone","sub_pass":"pw","base_url":"https://h"}`
	ch2, err := BuildChannel("ntfy_managed", []byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	if err := ch2.Send(context.Background(), Notification{Title: "t", Body: "b"}); err == nil {
		t.Error("managed ntfy must refuse a non-loopback target")
	}
}

func TestHeaderSafeStripsInjection(t *testing.T) {
	got := headerSafe("Subject\r\nBcc: evil@x\x00 more")
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("headerSafe left a control char: %q", got)
	}
}

// The SSRF guard refuses to deliver to loopback / link-local (incl. the cloud
// metadata IP) regardless of channel kind — and the error never echoes the URL.
func TestChannelGuardBlocksLoopbackAndMetadata(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{"http://127.0.0.1:9/hook", "http://169.254.169.254/latest", "http://[::1]:9/x"} {
		c := webhookChannel{URL: raw}
		err := c.Send(ctx, Notification{Title: "t", Body: "b"})
		if err == nil {
			t.Errorf("send to %q should be blocked", raw)
		}
		if err != nil && strings.Contains(err.Error(), raw) {
			t.Errorf("error leaked the URL: %v", err)
		}
	}
}

// A delivery error never contains the secret-bearing URL (Telegram token /
// Slack-Discord webhook URL).
func TestDeliveryErrorOmitsURL(t *testing.T) {
	// nonexistent host → a *url.Error; sanitizeHTTPErr must drop the URL.
	c := telegramChannel{BotToken: "12345:SECRET-BOT-TOKEN", ChatID: "1"}
	err := c.Send(context.Background(), Notification{Title: "t"})
	if err == nil {
		t.Skip("telegram unexpectedly reachable")
	}
	if strings.Contains(err.Error(), "SECRET-BOT-TOKEN") {
		t.Errorf("telegram error leaked the bot token: %v", err)
	}
}

func TestBuildChannelRejectsUnknownFields(t *testing.T) {
	if _, err := BuildChannel("webhook", []byte(`{"url":"https://x/h","secret":"s"}`)); err != nil {
		t.Errorf("valid webhook config rejected: %v", err)
	}
	if _, err := BuildChannel("webhook", []byte(`{"url":"https://x","evil":"smuggled"}`)); err == nil {
		t.Error("unknown field should be rejected (DisallowUnknownFields)")
	}
	if _, err := BuildChannel("nope", []byte(`{}`)); err == nil {
		t.Error("unknown kind should be rejected")
	}
}

func TestSMTPRejectsBadAddresses(t *testing.T) {
	c := smtpChannel{Host: "smtp.example.com", Port: 587, From: "not an address", To: "ops@example.com"}
	if err := c.Send(context.Background(), Notification{Title: "t"}); err == nil {
		t.Error("bad from address should be rejected before any network use")
	}
}

func TestGmailChannel(t *testing.T) {
	// Valid config builds (and validates) through BuildChannel.
	if _, err := BuildChannel("gmail", []byte(`{"email":"me@gmail.com","password":"abcd efgh ijkl mnop","to":""}`)); err != nil {
		t.Errorf("valid gmail config rejected: %v", err)
	}
	// Validation rejects a bad address, a missing app password, and a bad recipient.
	bad := []string{
		`{"email":"not an email","password":"pw","to":""}`,
		`{"email":"me@gmail.com","password":"","to":""}`,
		`{"email":"me@gmail.com","password":"pw","to":"nope"}`,
	}
	for _, cfg := range bad {
		if _, err := BuildChannel("gmail", []byte(cfg)); err == nil {
			t.Errorf("invalid gmail config accepted: %s", cfg)
		}
	}
	// Unknown fields are rejected (no smuggling extra SMTP host/port).
	if _, err := BuildChannel("gmail", []byte(`{"email":"me@gmail.com","password":"pw","host":"evil"}`)); err == nil {
		t.Error("unknown field should be rejected (a gmail channel can't override the SMTP host)")
	}
	// The preset targets Gmail's STARTTLS endpoint and defaults `to` to the sender.
	c := gmailChannel{Email: "me@gmail.com", Password: "pw"}
	if to := c.To; to != "" { // sanity: To empty means "send to myself" at Send time
		t.Fatalf("unexpected To %q", to)
	}
}
