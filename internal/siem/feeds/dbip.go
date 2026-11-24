package feeds

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/daboss2003/mooring/internal/siem/enrich"
)

// months is t's UTC month and the one before, as DB-IP names its files ("2026-11", "2026-10").
func months(t time.Time) (cur, prev string) {
	t = t.UTC()
	first := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return first.Format("2006-01"), first.AddDate(0, -1, 0).Format("2006-01")
}

// fetchDBIP installs this month's DB-IP Lite file, or last month's while this month's isn't
// published (404), when it is newer than the one in use; nothing newer is a success.
func (m *Manager) fetchDBIP(ctx context.Context, f *feed, now time.Time) (result, error) {
	cur, prev := months(now)
	m.mu.Lock()
	inUse := f.st.Version
	m.mu.Unlock()
	for _, ver := range []string{cur, prev} {
		if inUse != "" && ver <= inUse {
			return result{}, nil
		}
		err := m.installDBIP(ctx, f, ver)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return result{}, fmt.Errorf("%s: %w", ver, err)
		}
		return result{changed: true, version: ver}, nil
	}
	return result{}, fmt.Errorf("no DB-IP %s Lite file for %s or %s", f.kind, cur, prev)
}

// installDBIP downloads one DB-IP file (gzip, at most compCap bytes, at most rawCap once
// uncompressed) to a temporary file in Dir, opens and checks it (enrich.OpenDB), and only then
// renames it over the file in use and swaps it into the enricher. DB-IP publishes no checksum: a
// file that opens with the right metadata is the check. On any failure the file in use stays, and
// the temporary file is removed.
func (m *Manager) installDBIP(ctx context.Context, f *feed, ver string) error {
	resp, err := m.get(ctx, m.urls.dbip+"dbip-"+f.slug+"-lite-"+ver+".mmdb.gz", m.ua)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength > f.compCap {
		return fmt.Errorf("the download is larger than %s", sizeText(f.compCap))
	}
	tmp, file, err := createTemp(m.root, f.file)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		// Intentional: keyed on completion, not on an error, so a panic unwinding through here
		// (recovered by safeFetch) also closes and removes the temporary file (up to rawCap bytes).
		// Closing a closed file only returns an error; after the rename tmp no longer exists.
		if !installed {
			_ = file.Close()
			_ = m.root.Remove(tmp)
		}
	}()
	n, cerr := gunzip(file, resp.Body, f.compCap, f.rawCap)
	if err := file.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		return cerr
	}
	if n == 0 {
		return errors.New("the download is empty")
	}
	db, err := enrich.OpenDB(m.root, tmp, f.kind, f.rawCap)
	if err != nil {
		return err
	}
	if err := m.root.Rename(tmp, f.file); err != nil {
		db.Close()
		return err
	}
	installed = true
	if f.kind == enrich.KindCity {
		m.x.SetCity(db)
	} else {
		m.x.SetASN(db)
	}
	return nil
}

// gunzip writes the gzip stream r to w, synced; it fails past compCap bytes read or rawCap bytes
// written.
func gunzip(w interface {
	io.Writer
	Sync() error
}, r io.Reader, compCap, rawCap int64) (int64, error) {
	cr := &countingReader{r: io.LimitReader(r, compCap+1)}
	zr, err := gzip.NewReader(cr)
	if err != nil {
		if cr.n > compCap {
			return 0, fmt.Errorf("the download is larger than %s", sizeText(compCap))
		}
		return 0, fmt.Errorf("not a gzip file: %w", err)
	}
	n, err := io.Copy(w, io.LimitReader(zr, rawCap+1))
	switch {
	case cr.n > compCap:
		return n, fmt.Errorf("the download is larger than %s", sizeText(compCap))
	case n > rawCap:
		return n, fmt.Errorf("the database is larger than %s uncompressed", sizeText(rawCap))
	case err != nil:
		return n, fmt.Errorf("gunzip: %w", err)
	}
	return n, w.Sync()
}

// sizeText is n bytes in MiB when whole, else in bytes.
func sizeText(n int64) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// loadDBIP opens f's file on disk into the enricher. A version not in the state (lost) is the
// database's build month.
func (m *Manager) loadDBIP(f *feed) error {
	db, err := enrich.OpenDB(m.root, f.file, f.kind, f.rawCap)
	if err != nil {
		return err
	}
	if f.st.Version == "" {
		f.st.Version = db.Metadata().BuildTime().UTC().Format("2006-01")
	}
	if f.kind == enrich.KindCity {
		m.x.SetCity(db)
	} else {
		m.x.SetASN(db)
	}
	return nil
}
