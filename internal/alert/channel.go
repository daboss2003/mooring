package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Notification is the rendered alert handed to a channel. Title/Body are
// plain-text with minimal markdown — there is no template engine (plan §8: never
// one that could execute code).
type Notification struct {
	Title string
	Body  string
	Level string
}

// Channel delivers a Notification. Implementations use std-lib only.
type Channel interface {
	Send(ctx context.Context, n Notification) error
}

// BuildChannel constructs a channel from its kind + decrypted JSON config.
func BuildChannel(kind string, configJSON []byte) (Channel, error) {
	switch kind {
	case "webhook":
		return parseChannel[webhookChannel](configJSON)
	case "smtp":
		return parseChannel[smtpChannel](configJSON)
	case "gmail":
		ch, err := parseChannel[gmailChannel](configJSON)
		if err != nil {
			return nil, err
		}
		if verr := ch.(gmailChannel).validate(); verr != nil {
			return nil, verr
		}
		return ch, nil
	case "telegram":
		return parseChannel[telegramChannel](configJSON)
	case "slack":
		return parseChannel[slackChannel](configJSON)
	case "discord":
		return parseChannel[discordChannel](configJSON)
	case "ntfy":
		return parseChannel[ntfyChannel](configJSON)
	case "ntfy_managed":
		return parseChannel[ntfyManagedChannel](configJSON)
	default:
		return nil, fmt.Errorf("alert: unknown channel kind %q", kind)
	}
}

// ValidChannelKind reports whether kind is supported.
func ValidChannelKind(kind string) bool {
	switch kind {
	case "webhook", "smtp", "gmail", "telegram", "slack", "discord", "ntfy", "ntfy_managed":
		return true
	}
	return false
}

func parseChannel[T Channel](b []byte) (Channel, error) {
	var c T
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("alert: bad channel config: %w", err)
	}
	return c, nil
}

// --- SSRF-guarded outbound HTTP (plan §8 / §15 egress posture) ---

// errBlockedTarget rejects a dial to loopback/link-local (incl. the cloud
// metadata IP 169.254.169.254). Private/LAN is allowed so a self-hosted notifier
// (ntfy/gotify) still works; the metadata + loopback SSRF targets are killed.
var errBlockedTarget = errors.New("alert: refusing to deliver to a loopback/link-local address")

func guardedClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return errBlockedTarget
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return errBlockedTarget
		}
		return nil
	}
	return &http.Client{
		Timeout: timeout,
		// Never follow redirects (a 30x could bounce to a blocked target post-check).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

// sanitizeHTTPErr strips the (often SECRET-bearing) URL from an http.Client error
// before it is returned/logged/echoed: a Telegram bot token, or a Slack/Discord
// webhook URL, lives IN the request URL, and Go's *url.Error embeds that full URL
// (review: token/URL leak in errors → logs + the web test response). We surface
// only the underlying cause (timeout/refused/dns), never the URL.
func sanitizeHTTPErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("alert: delivery failed: %v", ue.Err)
	}
	return fmt.Errorf("alert: delivery failed")
}

func postJSON(ctx context.Context, target string, body any, hdr map[string]string) error {
	if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "http://") {
		return errors.New("alert: channel url must be http(s)")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return errors.New("alert: bad channel url")
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := guardedClient(20 * time.Second).Do(req)
	if err != nil {
		return sanitizeHTTPErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alert: channel returned status %d", resp.StatusCode)
	}
	return nil
}

func postText(ctx context.Context, target, body string, hdr map[string]string) error {
	return postTextWith(ctx, guardedClient(20*time.Second), target, body, hdr)
}

func postTextWith(ctx context.Context, client *http.Client, target, body string, hdr map[string]string) error {
	if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "http://") {
		return errors.New("alert: channel url must be http(s)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return errors.New("alert: bad channel url")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return sanitizeHTTPErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alert: channel returned status %d", resp.StatusCode)
	}
	return nil
}

// loopbackClient dials ONLY loopback — the inverse of guardedClient. It is used solely
// by the managed-ntfy channel, whose publish target is Mooring's OWN ntfy on
// 127.0.0.1 (which guardedClient rightly blocks for every operator-supplied channel).
// The positive loopback check means even a tampered config can't turn it into an
// off-host SSRF.
func loopbackClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Unmap().IsLoopback() {
			return errBlockedTarget
		}
		return nil
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
		},
	}
}

func isLoopbackHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// --- webhook (HMAC-signed) ---

type webhookChannel struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

func (c webhookChannel) Send(ctx context.Context, n Notification) error {
	payload := map[string]string{"title": n.Title, "body": n.Body, "level": n.Level}
	b, _ := json.Marshal(payload)
	hdr := map[string]string{}
	if c.Secret != "" {
		mac := hmac.New(sha256.New, []byte(c.Secret))
		mac.Write(b)
		hdr["X-Mooring-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	return postJSON(ctx, c.URL, json.RawMessage(b), hdr)
}

// --- slack / discord / ntfy / telegram (provider webhooks) ---

type slackChannel struct {
	WebhookURL string `json:"webhook_url"`
}

func (c slackChannel) Send(ctx context.Context, n Notification) error {
	return postJSON(ctx, c.WebhookURL, map[string]string{"text": n.Title + "\n" + n.Body}, nil)
}

type discordChannel struct {
	WebhookURL string `json:"webhook_url"`
}

func (c discordChannel) Send(ctx context.Context, n Notification) error {
	return postJSON(ctx, c.WebhookURL, map[string]string{"content": clip(n.Title+"\n"+n.Body, 1900)}, nil)
}

type ntfyChannel struct {
	URL   string `json:"url"` // base, e.g. https://ntfy.sh
	Topic string `json:"topic"`
	Token string `json:"token"` // optional bearer
}

func (c ntfyChannel) Send(ctx context.Context, n Notification) error {
	hdr := map[string]string{"X-Title": headerSafe(n.Title)}
	if c.Token != "" {
		hdr["Authorization"] = "Bearer " + c.Token
	}
	target := strings.TrimRight(c.URL, "/") + "/" + c.Topic
	return postText(ctx, target, n.Body, hdr)
}

// ntfyManagedChannel publishes to Mooring's OWN managed ntfy over loopback. URL is set
// by Mooring (a 127.0.0.1 publish endpoint), Token is the WRITE-only token. SubUser,
// SubPass and BaseURL are carried so the dashboard can show the operator how to
// subscribe; they are not used to send (the struct lists them so DisallowUnknownFields
// accepts the config). Send re-checks the target is loopback and uses the loopback-only
// client.
type ntfyManagedChannel struct {
	URL     string `json:"url"`
	Topic   string `json:"topic"`
	Token   string `json:"token"`
	SubUser string `json:"sub_user"`
	SubPass string `json:"sub_pass"`
	BaseURL string `json:"base_url"`
}

func (c ntfyManagedChannel) Send(ctx context.Context, n Notification) error {
	if !isLoopbackHTTPURL(c.URL) {
		return errors.New("alert: managed ntfy target must be loopback")
	}
	hdr := map[string]string{"X-Title": headerSafe(n.Title)}
	if c.Token != "" {
		hdr["Authorization"] = "Bearer " + c.Token
	}
	target := strings.TrimRight(c.URL, "/") + "/" + c.Topic
	return postTextWith(ctx, loopbackClient(20*time.Second), target, n.Body, hdr)
}

type telegramChannel struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

func (c telegramChannel) Send(ctx context.Context, n Notification) error {
	// The bot token MUST live in the Telegram API path; postJSON/sanitizeHTTPErr
	// strip the URL from any returned error so the token never leaks to logs/UI.
	target := "https://api.telegram.org/bot" + c.BotToken + "/sendMessage"
	return postJSON(ctx, target, map[string]string{"chat_id": c.ChatID, "text": n.Title + "\n" + n.Body}, nil)
}

// --- SMTP (TLS, header-injection-safe) ---

type smtpChannel struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	To       string `json:"to"`
}

func (c smtpChannel) Send(ctx context.Context, n Notification) error {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return fmt.Errorf("alert: bad from address")
	}
	to, err := mail.ParseAddress(c.To)
	if err != nil {
		return fmt.Errorf("alert: bad to address")
	}
	// Build the message via discrete, header-safe fields — every interpolated
	// value is CR/LF/NUL-stripped so an attacker-controlled app/host name in the
	// subject can never inject a header / BCC (plan §8.4 red-team).
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", from.String())
	fmt.Fprintf(&msg, "To: %s\r\n", to.String())
	fmt.Fprintf(&msg, "Subject: %s\r\n", headerSafe(n.Title))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(strings.ReplaceAll(n.Body, "\r\n", "\n"))

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}

	if c.Port == 465 { // implicit TLS
		return sendImplicitTLS(addr, c.Host, tlsCfg, auth, from.Address, []string{to.Address}, msg.Bytes())
	}
	// STARTTLS path (587/25) — REQUIRE TLS (never send credentials in the clear).
	return sendStartTLS(addr, tlsCfg, auth, from.Address, []string{to.Address}, msg.Bytes())
}

// --- Gmail (a zero-config preset over SMTP) ---

// gmailChannel is the easy email option: the operator supplies only their Gmail address
// and a Google App Password, and Mooring fills in the SMTP details (smtp.gmail.com:587,
// STARTTLS) and reuses the header-injection-safe smtpChannel sender. NOTE: Gmail SMTP
// requires an App Password (16 chars, from a 2FA-enabled account) — a normal account
// password is rejected by Google.
type gmailChannel struct {
	Email    string `json:"email"`    // the Gmail address: SMTP username AND the From
	Password string `json:"password"` // a Google App Password (never the account password)
	To       string `json:"to"`       // recipient; defaults to Email (send to yourself) when empty
}

func (c gmailChannel) validate() error {
	if _, err := mail.ParseAddress(c.Email); err != nil {
		return errors.New("alert: the Gmail address is not a valid email")
	}
	if strings.TrimSpace(c.Password) == "" {
		return errors.New("alert: a Google App Password is required (a normal Gmail password will not work)")
	}
	if c.To != "" {
		if _, err := mail.ParseAddress(c.To); err != nil {
			return errors.New("alert: the recipient (to) is not a valid email")
		}
	}
	return nil
}

func (c gmailChannel) Send(ctx context.Context, n Notification) error {
	to := c.To
	if to == "" {
		to = c.Email // default: send the alerts to yourself
	}
	return smtpChannel{
		Host:     "smtp.gmail.com",
		Port:     587, // STARTTLS (the smtpChannel sender REQUIRES TLS)
		Username: c.Email,
		Password: c.Password,
		From:     c.Email,
		To:       to,
	}.Send(ctx, n)
}

func sendStartTLS(addr string, tlsCfg *tls.Config, auth smtp.Auth, from string, to []string, msg []byte) error {
	cl, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("alert: smtp dial failed")
	}
	defer cl.Close()
	if ok, _ := cl.Extension("STARTTLS"); !ok {
		return errors.New("alert: SMTP server does not support STARTTLS (refusing to send in the clear)")
	}
	if err := cl.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("alert: smtp starttls failed")
	}
	return finishSMTP(cl, auth, from, to, msg)
}

func sendImplicitTLS(addr, host string, tlsCfg *tls.Config, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("alert: smtp tls dial failed")
	}
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("alert: smtp client failed")
	}
	defer cl.Close()
	return finishSMTP(cl, auth, from, to, msg)
}

func finishSMTP(cl *smtp.Client, auth smtp.Auth, from string, to []string, msg []byte) error {
	if auth != nil {
		if err := cl.Auth(auth); err != nil {
			return fmt.Errorf("alert: smtp auth failed")
		}
	}
	if err := cl.Mail(from); err != nil {
		return fmt.Errorf("alert: smtp MAIL failed")
	}
	for _, t := range to {
		if err := cl.Rcpt(t); err != nil {
			return fmt.Errorf("alert: smtp RCPT failed")
		}
	}
	wc, err := cl.Data()
	if err != nil {
		return fmt.Errorf("alert: smtp DATA failed")
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return fmt.Errorf("alert: smtp write failed")
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("alert: smtp close failed")
	}
	return cl.Quit()
}

// headerSafe strips CR/LF/NUL so a value can never inject an email/HTTP header.
func headerSafe(s string) string {
	return clip(strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(s), 200)
}

func clip(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
