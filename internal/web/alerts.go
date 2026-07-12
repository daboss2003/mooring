package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/audit"
)

// M10 alerting UI. Channels are write-only (secrets never rendered back); rules
// drive the read-and-notify engine; operators ack/silence open alerts.

type alertRuleView struct {
	ID                   int64
	Name, Kind, Scope    string
	Threshold            float64
	ForSeconds           int
	Level                string
	DeferWhenSelfManaged bool
	Enabled              bool
}

type firingView struct {
	RuleID int64
	Target string
	Level  string
	Detail string
	Since  int64 // unix seconds; the "ts" template renders it localised
	Acked  bool
}

type alertsView struct {
	Channels    []alertstore.ChannelMeta
	Rules       []alertRuleView
	Firing      []firingView
	ManagedNtfy *alertstore.NtfyManagedInfo // the Mooring-hosted ntfy subscribe info, if configured
	EdgeOwned   bool                        // managed ntfy needs the managed edge to expose it
}

// handleAlerts (GET /alerts) is the VIEW page: open alerts + counts, with links to the
// dedicated Channels and Rules pages.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	av := &alertsView{}
	if firing, err := s.alertStore.FiringStates(); err == nil {
		for _, f := range firing {
			av.Firing = append(av.Firing, firingView{
				RuleID: f.RuleID, Target: f.Target, Level: f.Level, Detail: f.Detail,
				Since: f.Since, Acked: f.Acked,
			})
		}
	}
	av.Channels, _ = s.alertStore.ListChannels() // for the "Channels (N)" link count
	if rules, err := s.alertStore.ListRules(); err == nil {
		av.Rules = make([]alertRuleView, len(rules)) // count only here
	}
	s.render(w, r, "alerts.html", tmplData{
		Title: "Alerts — Mooring", CSRFToken: CSRFToken(r.Context()), Username: sessionUser(r), Alerts: av,
	})
}

// handleChannelsPage (GET /alerts/channels) is the dedicated channels page: list +
// create + delete + test, plus the Mooring-hosted ntfy subscribe info.
func (s *Server) handleChannelsPage(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	av := &alertsView{}
	av.Channels, _ = s.alertStore.ListChannels()
	if info, ok, err := s.alertStore.ManagedNtfy(); err == nil && ok {
		av.ManagedNtfy = &info
	}
	av.EdgeOwned = s.edgeRoutes != nil && s.edgeRecon != nil && s.runner != nil
	s.render(w, r, "channels.html", tmplData{
		Title: "Alert channels — Mooring", CSRFToken: CSRFToken(r.Context()), Username: sessionUser(r),
		Error: r.URL.Query().Get("err"), Alerts: av,
	})
}

// handleRulesPage (GET /alerts/rules) is the dedicated rules page: list + create +
// delete. Channels are loaded so the rule form can offer them in a select.
func (s *Server) handleRulesPage(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	av := &alertsView{}
	if rules, err := s.alertStore.ListRules(); err == nil {
		for _, ru := range rules {
			av.Rules = append(av.Rules, alertRuleView{
				ID: ru.ID, Name: ru.Name, Kind: ru.Kind, Scope: ru.Scope, Threshold: ru.Threshold,
				ForSeconds: ru.ForSeconds, Level: ru.Level, DeferWhenSelfManaged: ru.DeferWhenSelfManaged, Enabled: ru.Enabled,
			})
		}
	}
	av.Channels, _ = s.alertStore.ListChannels()
	s.render(w, r, "rules.html", tmplData{
		Title: "Alert rules — Mooring", CSRFToken: CSRFToken(r.Context()), Username: sessionUser(r),
		Error: r.URL.Query().Get("err"), Alerts: av,
	})
}

// buildChannelConfig assembles the kind-specific JSON config from the form. Only
// the fields relevant to the kind are read, so a stray field can't be smuggled in.
func buildChannelConfig(kind string, r *http.Request) ([]byte, bool) {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	m := map[string]any{}
	switch kind {
	case "webhook":
		m["url"], m["secret"] = v("url"), v("secret")
	case "slack":
		m["webhook_url"] = v("webhook_url")
	case "discord":
		m["webhook_url"] = v("webhook_url")
	case "ntfy":
		m["url"], m["topic"], m["token"] = v("url"), v("topic"), v("token")
	case "telegram":
		m["bot_token"], m["chat_id"] = v("bot_token"), v("chat_id")
	case "smtp":
		port, _ := strconv.Atoi(v("port"))
		m["host"], m["port"], m["username"], m["password"], m["from"], m["to"] =
			v("host"), port, v("username"), v("password"), v("from"), v("to")
	case "gmail":
		// Easy email: just the Gmail address + a Google App Password (+ optional recipient).
		m["email"], m["password"], m["to"] = v("gmail_email"), v("gmail_password"), v("gmail_to")
	default:
		return nil, false
	}
	b, err := json.Marshal(m)
	return b, err == nil
}

func (s *Server) handleAlertChannelSave(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.PostFormValue("name"))
	kind := strings.TrimSpace(r.PostFormValue("kind"))
	if kind == "ntfy_managed" {
		s.provisionManagedNtfy(w, r, name)
		return
	}
	cfg, ok := buildChannelConfig(kind, r)
	if !ok {
		http.Error(w, "unknown channel kind", http.StatusUnprocessableEntity)
		return
	}
	if err := s.alertStore.SaveChannel(r.Context(), name, kind, cfg); err != nil {
		http.Error(w, "channel rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_channel_save", Target: name, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/alerts/channels", http.StatusSeeOther)
}

func (s *Server) handleAlertChannelDelete(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	// If this is the Mooring-hosted ntfy, tear its container + edge route down too.
	if kind, err := s.alertStore.ChannelKind(id); err == nil && kind == "ntfy_managed" {
		s.teardownManagedNtfy(r.Context())
	}
	_ = s.alertStore.DeleteChannel(r.Context(), id)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_channel_delete", Target: strconv.FormatInt(id, 10), Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/alerts/channels", http.StatusSeeOther)
}

// handleAlertChannelTest sends a test notification through one channel. Channel
// Send errors are already URL/secret-redacted (see alert.sanitizeHTTPErr), so
// echoing them cannot leak a bot token / webhook URL.
func (s *Server) handleAlertChannelTest(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	// The "send test" button (lc-btn) POSTs with the id in the QUERY string, so read it
	// with FormValue (query+body), not PostFormValue (body only) — otherwise id=0 and
	// the channel never resolves ("could not build channel").
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	ch, err := s.alertStore.ChannelByID(id)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("could not build channel\n"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	n := alert.Notification{Title: "[test] Mooring alert channel", Body: "This is a test notification from Mooring.", Level: alert.LevelWarning}
	if err := ch.Send(ctx, n); err != nil {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_channel_test", Target: strconv.FormatInt(id, 10), Outcome: audit.Error, Level: audit.Security})
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("send failed: " + err.Error() + "\n"))
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_channel_test", Target: strconv.FormatInt(id, 10), Outcome: audit.OK, Level: audit.Security})
	_, _ = w.Write([]byte("test notification sent.\n"))
}

func (s *Server) handleAlertRuleSave(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	threshold, _ := strconv.ParseFloat(r.PostFormValue("threshold"), 64)
	forSec, _ := strconv.Atoi(r.PostFormValue("for_seconds"))
	chID, _ := strconv.ParseInt(r.PostFormValue("channel_id"), 10, 64)
	rule := alert.Rule{
		ID: id, Name: strings.TrimSpace(r.PostFormValue("name")), Kind: r.PostFormValue("kind"),
		Scope: strings.TrimSpace(r.PostFormValue("scope")), Threshold: threshold, ForSeconds: forSec,
		Level: r.PostFormValue("level"), DeferWhenSelfManaged: r.PostFormValue("defer") == "on",
		ChannelID: chID, Enabled: r.PostFormValue("enabled") == "on",
	}
	if err := s.alertStore.SaveRule(r.Context(), rule); err != nil {
		http.Error(w, "rule rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_rule_save", Target: rule.Name, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/alerts/rules", http.StatusSeeOther)
}

func (s *Server) handleAlertRuleDelete(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	_ = s.alertStore.DeleteRule(r.Context(), id)
	http.Redirect(w, r, "/alerts/rules", http.StatusSeeOther)
}

func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	ruleID, _ := strconv.ParseInt(r.PostFormValue("rule_id"), 10, 64)
	_ = s.alertStore.Ack(r.Context(), ruleID, r.PostFormValue("target"))
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_ack", Target: r.PostFormValue("target"), Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}

func (s *Server) handleAlertSilence(w http.ResponseWriter, r *http.Request) {
	if s.alertStore == nil {
		http.Error(w, "alerting unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	ruleID, _ := strconv.ParseInt(r.PostFormValue("rule_id"), 10, 64)
	mins, _ := strconv.Atoi(r.PostFormValue("minutes"))
	if mins <= 0 {
		mins = 60
	}
	until := time.Now().Add(time.Duration(mins) * time.Minute).Unix()
	_ = s.alertStore.Silence(r.Context(), ruleID, r.PostFormValue("target"), until)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "alert_silence", Target: r.PostFormValue("target"), Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}
