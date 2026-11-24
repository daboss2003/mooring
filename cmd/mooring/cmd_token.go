package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/store"
)

// cmdToken is the SSH-only scoped-API-token surface (plan §17.1). Minting lives ONLY
// here — the web plane never mints a token (that would be a privilege-escalation
// surface). The one-time plaintext is printed ONCE to stdout; only the argon2id hash
// is stored.
func cmdToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mooring token <mint|list|revoke> [flags]")
	}
	switch args[0] {
	case "mint":
		return cmdTokenMint(args[1:])
	case "list":
		return cmdTokenList(args[1:])
	case "revoke":
		return cmdTokenRevoke(args[1:])
	default:
		return fmt.Errorf("unknown token subcommand %q (try: mint, list, revoke)", args[0])
	}
}

func openTokenStore(configPath string) (*store.DB, *apitoken.Store, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "mooring.db"))
	if err != nil {
		return nil, nil, err
	}
	if err := checkKeySentinel(cfg, db); err != nil {
		db.Close()
		return nil, nil, err
	}
	return db, apitoken.NewStore(db), nil
}

func cmdTokenMint(args []string) error {
	fs := flag.NewFlagSet("token mint", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	scopesCSV := fs.String("scopes", "", "comma-separated scopes: status:read, metrics:read, events:read, audit:read, deploy:write:<slug>")
	cidrsCSV := fs.String("cidrs", "", "comma-separated CIDR set the token is valid from (non-empty; a catch-all is refused)")
	ttl := fs.Duration("ttl", 0, "token lifetime (mandatory, e.g. 720h); a token always expires")
	label := fs.String("label", "", "operator note (informational)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scopesCSV == "" || *cidrsCSV == "" || *ttl <= 0 {
		return fmt.Errorf("usage: mooring token mint --scopes <list> --cidrs <list> --ttl <dur> [--label <s>]")
	}
	scopes := splitCSV(*scopesCSV)
	cidrs := splitCSV(*cidrsCSV)

	db, ts, err := openTokenStore(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	now := time.Now()
	m, err := apitoken.Mint(scopes, cidrs, *ttl, now)
	if err != nil {
		return err // scope/CIDR/ttl validation (the structural guards) happen here
	}
	ev := audit.Event{Action: "api_token_mint", Target: m.Record.ID, Outcome: audit.OK}
	if err := ts.Insert(context.Background(), m.Record, *label, now); err != nil {
		ev.Outcome, ev.Detail = audit.Error, "store failed"
		cliAudit(db, ev)
		return err
	}
	nets := make([]string, 0, len(m.Record.CIDRs))
	for _, p := range m.Record.CIDRs {
		nets = append(nets, p.String())
	}
	ev.Detail = fmt.Sprintf("scopes=%s cidrs=%s expires=%s label=%q", strings.Join(m.Record.Scopes, ","),
		strings.Join(nets, ","), time.Unix(m.Record.ExpiresAt, 0).UTC().Format(time.RFC3339), *label)
	cliAudit(db, ev)

	fmt.Println("token minted — copy the value below, it is shown ONCE and cannot be recovered:")
	fmt.Println()
	fmt.Println("  " + m.Plaintext)
	fmt.Println()
	fmt.Printf("id:      %s\n", m.Record.ID)
	fmt.Printf("scopes:  %s\n", strings.Join(m.Record.Scopes, " "))
	fmt.Printf("cidrs:   %s\n", *cidrsCSV)
	fmt.Printf("expires: %s\n", time.Unix(m.Record.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("the IP gate admits the token's CIDRs only after a reload:")
	fmt.Println("  systemctl reload mooring   (or: kill -HUP <pid>)")
	return nil
}

func cmdTokenList(args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, ts, err := openTokenStore(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	recs, err := ts.List(context.Background())
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Println("no API tokens")
		return nil
	}
	now := time.Now().Unix()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tEXPIRES\tSCOPES")
	for _, r := range recs {
		state := "active"
		switch {
		case r.Revoked:
			state = "revoked"
		case r.ExpiresAt <= now:
			state = "expired"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, state,
			time.Unix(r.ExpiresAt, 0).UTC().Format(time.RFC3339), strings.Join(r.Scopes, " "))
	}
	return tw.Flush()
}

func cmdTokenRevoke(args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	id := fs.String("id", "", "token id to revoke")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("usage: mooring token revoke --id <token-id>")
	}
	db, ts, err := openTokenStore(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()

	err = ts.Revoke(context.Background(), *id)
	ev := audit.Event{Action: "api_token_revoke_cli", Target: apitoken.AuditTarget(*id), Outcome: audit.OK}
	if err != nil {
		ev.Outcome, ev.Detail = audit.Error, "revoke failed"
		if errors.Is(err, apitoken.ErrNotFound) {
			ev.Detail = "no such token id"
		}
	}
	cliAudit(db, ev)
	if err != nil {
		return err
	}
	fmt.Printf("token %s revoked — it is rejected at auth immediately; reload to drop it from the IP gate union\n", *id)
	return nil
}

// cliAudit records a CLI action as a security event in the events table: actor cliActor(),
// IP "local". A failed write is reported on stderr and doesn't fail the command, which has
// already done its work.
func cliAudit(db *store.DB, e audit.Event) {
	e.Actor, e.IP, e.Level = cliActor(), "local", audit.Security
	if err := audit.New(db, nil).Log(context.Background(), e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record %s in the audit log: %v\n", e.Action, err)
	}
}

// cliActor names who ran the command: "cli:" + the sudo caller ($SUDO_USER), else the
// effective user (its uid when it has no name).
func cliActor() string {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		uid := strconv.Itoa(os.Geteuid())
		name = "uid " + uid
		if u, err := user.LookupId(uid); err == nil && u.Username != "" {
			name = u.Username
		}
	}
	var b strings.Builder
	for _, r := range name {
		if !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > 64 {
			break
		}
		b.WriteRune(r)
	}
	return "cli:" + b.String()
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
