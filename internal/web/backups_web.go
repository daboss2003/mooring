package web

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
)

// The Backups screen lets the operator take, review, download, and delete encrypted
// snapshots of Mooring's own state (every app's config, definitions, routes, and
// already-encrypted secrets). The archive is AES-256-GCM-encrypted with the master
// key, so it's safe to keep or move off-box; restoring needs that same key.

type backupRow struct {
	ID   string
	When int64 // unix seconds; the "ts" template renders it localised
	Size string
	SHA  string
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		notFound(w)
		return
	}
	data := tmplData{
		Title:         "Backups — Mooring",
		CSRFToken:     CSRFToken(r.Context()),
		Username:      sessionUser(r),
		BackupEnabled: s.backups.Available(),
		Error:         r.URL.Query().Get("err"),
	}
	recs, err := s.backups.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, rc := range recs {
		sha := rc.SHA256
		if len(sha) > 12 {
			sha = sha[:12]
		}
		data.BackupRows = append(data.BackupRows, backupRow{
			ID:   rc.ID,
			When: rc.CreatedAt,
			Size: humanBytes(uint64(rc.SizeBytes)),
			SHA:  sha,
		})
	}
	s.render(w, r, "backups.html", data)
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil || !s.backups.Available() {
		http.Error(w, "backups unavailable", http.StatusServiceUnavailable)
		return
	}
	_, err := s.backups.Create(r.Context(), time.Now())
	outcome := audit.OK
	dest := "/settings/backups"
	if err != nil {
		outcome = audit.Error
		dest = "/settings/backups?err=" + url.QueryEscape("backup failed: "+err.Error())
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "backup_create",
		Outcome: outcome, Level: audit.Security,
	})
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		notFound(w)
		return
	}
	id := r.PostFormValue("id")
	err := s.backups.Delete(r.Context(), id)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "backup_delete",
		Target: id, Outcome: outcome, Level: audit.Security,
	})
	http.Redirect(w, r, "/settings/backups", http.StatusSeeOther)
}

// handleBackupDownload streams the encrypted archive (ciphertext — safe off-box). The
// id selects a catalogued record; the served path is always a generated <id>.mbk
// confined to the backups dir, never a client-supplied path.
func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		notFound(w)
		return
	}
	rec, ok, err := s.backups.Get(r.Context(), r.URL.Query().Get("id"))
	if err != nil || !ok {
		notFound(w)
		return
	}
	f, err := os.Open(s.backups.FilePath(rec))
	if err != nil {
		notFound(w)
		return
	}
	defer f.Close()
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "backup_download",
		Target: rec.ID, Outcome: audit.OK, Level: audit.Security,
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="mooring-backup-`+rec.ID+`.mbk"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}
