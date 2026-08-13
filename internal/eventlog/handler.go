package eventlog

import (
	"context"
	"log/slog"
	"sort"
	"strings"
)

// Handler is a slog.Handler that TEES WARN+ERROR records into the Store (for the Activity tab) while
// passing EVERY record through to the wrapped base handler (journald) unchanged. A store hiccup never
// blocks or errors the log path — Record is O(1) amortized and lock-guarded.
type Handler struct {
	base  slog.Handler
	store *Store
	attrs []slog.Attr // accumulated from WithAttrs (e.g. a logger built with .With("project", x))
}

// NewHandler wraps base so WARN+ERROR records are also captured in store.
func NewHandler(base slog.Handler, store *Store) *Handler {
	return &Handler{base: base, store: store}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.base.Enabled(ctx, l) }

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.store != nil && r.Level >= slog.LevelWarn {
		h.store.Record(r.Level.String(), r.Message, renderAttrs(h.attrs, r))
	}
	return h.base.Handle(ctx, r)
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(as))
	merged = append(merged, h.attrs...)
	merged = append(merged, as...)
	return &Handler{base: h.base.WithAttrs(as), store: h.store, attrs: merged}
}

// WithGroup is passed through for the base handler's formatting; the event store flattens attrs, so
// group nesting doesn't change the dedup key.
func (h *Handler) WithGroup(g string) slog.Handler {
	return &Handler{base: h.base.WithGroup(g), store: h.store, attrs: h.attrs}
}

// renderAttrs flattens the handler's accumulated attrs plus the record's own attrs into a stable,
// sorted "k=v k=v" string — the dedup discriminator AND the context shown in the Activity tab.
// Sorting makes dedup order-independent. No extra redaction: Mooring's WARN/ERROR logs are already
// credential-free by design.
func renderAttrs(base []slog.Attr, r slog.Record) string {
	pairs := make([]string, 0, len(base)+r.NumAttrs())
	appendAttr := func(a slog.Attr) {
		if a.Key == "" {
			return
		}
		pairs = append(pairs, a.Key+"="+a.Value.String())
	}
	for _, a := range base {
		appendAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(a)
		return true
	})
	sort.Strings(pairs)
	return strings.Join(pairs, " ")
}
