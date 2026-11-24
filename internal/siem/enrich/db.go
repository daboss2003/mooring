package enrich

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Database kinds for OpenDB: the word DatabaseType must contain.
const (
	KindCity = "City"
	KindASN  = "ASN"
)

// verifyMax is the largest file OpenDB checks in full (maxminddb's Verify walks every node and
// record). Intentional: DB-IP's City Lite (about 130 MB) is past it — a full check takes seconds
// and over a gigabyte of allocations, more than the service's memory limit — so it is checked by
// its metadata and sample lookups only; the ASN Lite file (about 10 MB) is checked in full.
const verifyMax = 64 << 20

// metadataMarker starts a MaxMind DB's metadata section.
var metadataMarker = []byte("\xAB\xCD\xEFMaxMind.com")

// probeAddrs are looked up (and decoded) when a database is opened.
var probeAddrs = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("41.58.1.1"),
	netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("2a00:1450:4001::1"),
}

// DB is an open MaxMind DB file: memory-mapped read-only (read into memory where mmap isn't
// available) and reference-counted, so a database swapped out of an Enricher is unmapped only
// after the last lookup using it ends. The opener holds one reference: hand it to an Enricher
// (SetCity / SetASN, which take it over) or Close it.
type DB struct {
	r         *maxminddb.Reader
	data      []byte
	unmap     func([]byte) error
	refs      atomic.Int64 // 1 for the owner + 1 per lookup in flight; 0 = closed
	ownerGone atomic.Bool  // Close was called
}

// cityRecord and asnRecord are the parts of a record Enrich uses (DB-IP Lite's layout, the same as
// GeoLite2's).
type cityRecord struct {
	City struct {
		Names struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// OpenDB opens the MaxMind DB file name through root and checks it: a regular file (not a symlink)
// of at most maxSize bytes, binary format 2, an IPv4 or IPv6 tree with nodes and records, a
// DatabaseType containing kind (KindCity or KindASN), and a few lookups that decode. A file of at
// most 64 MiB is also verified in full (every node and record). Any failure leaves nothing open.
func OpenDB(root *os.Root, name, kind string, maxSize int64) (d *DB, err error) {
	if kind != KindCity && kind != KindASN {
		return nil, fmt.Errorf("enrich: unknown database kind %q", kind)
	}
	lfi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !lfi.Mode().IsRegular() {
		return nil, fmt.Errorf("enrich: %s is not a regular file", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(lfi, fi) {
		return nil, fmt.Errorf("enrich: %s changed while it was opened", name)
	}
	switch size := fi.Size(); {
	case size == 0:
		return nil, fmt.Errorf("enrich: %s is empty", name)
	case size > maxSize:
		return nil, fmt.Errorf("enrich: %s is larger than %d bytes", name, maxSize)
	}
	data, unmap, err := mapFile(f, int(fi.Size()))
	if err != nil {
		return nil, fmt.Errorf("enrich: map %s: %w", name, err)
	}
	db := &DB{data: data, unmap: unmap}
	defer func() {
		// Intentional: a panic in the reader on a hostile file fails the open instead of the service.
		if v := recover(); v != nil {
			d, err = nil, fmt.Errorf("enrich: %s: the database reader failed (%T)", name, v)
		}
		if err != nil {
			db.free()
		}
	}()
	if db.r, err = maxminddb.OpenBytes(data); err != nil {
		return nil, fmt.Errorf("enrich: %s: %w", name, err)
	}
	if err := check(db.r, data, kind); err != nil {
		return nil, fmt.Errorf("enrich: %s: %w", name, err)
	}
	db.refs.Store(1)
	return db, nil
}

// check is OpenDB's content check.
func check(r *maxminddb.Reader, data []byte, kind string) error {
	md := r.Metadata
	if !strings.Contains(md.DatabaseType, kind) {
		return fmt.Errorf("database type %q is not a %s database", cutForError(md.DatabaseType), kind)
	}
	if md.BinaryFormatMajorVersion != 2 {
		return fmt.Errorf("binary format %d is not 2", md.BinaryFormatMajorVersion)
	}
	if md.IPVersion != 4 && md.IPVersion != 6 {
		return fmt.Errorf("ip version %d", md.IPVersion)
	}
	if md.RecordSize != 24 && md.RecordSize != 28 && md.RecordSize != 32 {
		return fmt.Errorf("record size %d", md.RecordSize)
	}
	if md.NodeCount == 0 {
		return errors.New("no nodes")
	}
	// The data section lies between the tree (+ a 16-byte separator) and the metadata.
	meta := bytes.LastIndex(data, metadataMarker)
	tree := uint64(md.NodeCount) * uint64(md.RecordSize/4)
	if meta < 0 || tree+16 >= uint64(meta) {
		return errors.New("no records")
	}
	if len(data) <= verifyMax {
		if err := r.Verify(); err != nil {
			return err
		}
	}
	for _, a := range probeAddrs {
		if md.IPVersion == 4 && a.Is6() {
			continue
		}
		res := r.Lookup(a)
		var err error
		if kind == KindCity {
			var rec cityRecord
			err = res.Decode(&rec)
		} else {
			var rec asnRecord
			err = res.Decode(&rec)
		}
		if err != nil {
			return fmt.Errorf("lookup of %s: %w", a, err)
		}
	}
	return nil
}

// Metadata is the database's metadata.
func (d *DB) Metadata() maxminddb.Metadata { return d.r.Metadata }

// Close drops the owner's reference: the database is unmapped now, or when the last lookup using it
// ends. A second Close does nothing.
func (d *DB) Close() error {
	if d != nil && !d.ownerGone.Swap(true) {
		d.release()
	}
	return nil
}

// acquire takes a reference for a lookup; false once the database is closed.
func (d *DB) acquire() bool {
	for {
		n := d.refs.Load()
		if n <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// release drops a reference; the last one unmaps the file.
func (d *DB) release() {
	if d.refs.Add(-1) == 0 {
		d.free()
	}
}

func (d *DB) free() {
	if d.r != nil {
		_ = d.r.Close()
	}
	if d.data != nil && d.unmap != nil {
		_ = d.unmap(d.data)
	}
	d.data = nil
}

// closed reports whether the database was unmapped (tests).
func (d *DB) closed() bool { return d.refs.Load() <= 0 }

func cutForError(s string) string {
	s = cleanText(s, 64)
	if s == "" {
		return "(none)"
	}
	return s
}
