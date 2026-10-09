package web

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// A verified webhook that arrives while another git operation holds the single-flight gate used to be
// answered 202 "busy" and dropped, so that push was never deployed. It is now queued instead: at most
// one entry per app (or per preview PR) — the fetch that eventually runs picks up the newest commit, so
// later webhooks for the same target add nothing — and entries run in arrival order as soon as the gate
// is free. The queue is in memory: entries still waiting when Mooring stops are lost.
//
// An API deploy request (api_deploy.go) that finds the gate busy queues the same way, under its own key
// "api:<slug>": a waiting webhook entry for the app deploys only with auto-deploy on, so it must not
// absorb an API request, which deploys either way. A later API request for the same app hands the
// waiting entry its own token and address.

// pendingDeployPoll is how often a waiting queue re-tries the gate (a new entry also nudges it at once).
const pendingDeployPoll = 5 * time.Second

// queuedDeployFn runs one queued entry (a test seam; nil = the real run).
type queuedDeployFn func(ctx context.Context, d pendingDeploy)

// queuedFromAPI marks a pendingDeploy queued by an API deploy request.
const queuedFromAPI = "api"

// pendingDeploy is one queued webhook or API deploy request.
type pendingDeploy struct {
	key     string // "app:<slug>", "pr:<base>#<n>" or "api:<slug>"
	project string // the app slug; for a preview, its base app
	pr      int    // the pull request number of a preview deploy; 0 otherwise
	source  string // queuedFromAPI for an API deploy request; "" for a webhook
	tokenID string // the newest API request's token id (re-checked when the entry runs; audit actor "api:<id>")
	ip      string // the newest API request's client address, for its audit trail
	queued  time.Time
}

func appQueueKey(slug string) string        { return "app:" + slug }
func prQueueKey(base string, pr int) string { return "pr:" + base + "#" + strconv.Itoa(pr) }
func apiQueueKey(slug string) string        { return "api:" + slug }

// deployQueue is the FIFO of pending deploys, unique by key.
type deployQueue struct {
	mu    sync.Mutex
	items []pendingDeploy
	wake  chan struct{}
}

func newDeployQueue() *deployQueue { return &deployQueue{wake: make(chan struct{}, 1)} }

// add queues d unless an entry with the same key is already waiting; it reports whether d was added.
// A waiting API entry takes the newer request's token and address (it keeps its place in the queue).
func (q *deployQueue) add(d pendingDeploy) bool {
	q.mu.Lock()
	for i, it := range q.items {
		if it.key == d.key {
			// Intentional: the newest valid trigger wins. The entry re-checks its token when it runs, so
			// keeping the first request's token would drop a later, valid request once that token is
			// revoked, and the audit trail would name the wrong token.
			if d.source == queuedFromAPI && it.source == queuedFromAPI {
				q.items[i].tokenID, q.items[i].ip = d.tokenID, d.ip
			}
			q.mu.Unlock()
			return false
		}
	}
	q.items = append(q.items, d)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// remove drops a waiting entry (a PR closed before its queued preview deploy ran).
func (q *deployQueue) remove(key string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, it := range q.items {
		if it.key == key {
			q.items = append(q.items[:i], q.items[i+1:]...)
			return true
		}
	}
	return false
}

// empty reports whether nothing is waiting.
func (q *deployQueue) empty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) == 0
}

// pop takes the oldest entry.
func (q *deployQueue) pop() (pendingDeploy, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return pendingDeploy{}, false
	}
	d := q.items[0]
	q.items = q.items[1:]
	return d, true
}

// keys lists the waiting entries' keys in order.
func (q *deployQueue) keys() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, len(q.items))
	for i, it := range q.items {
		out[i] = it.key
	}
	return out
}

// RunPendingDeploys drains the deploy queue until ctx ends: whenever the git/deploy gate is free it
// starts the oldest queued entry (an app's fetch-and-auto-deploy, a PR preview deploy, or an API deploy).
func (s *Server) RunPendingDeploys(ctx context.Context) {
	t := time.NewTicker(pendingDeployPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.deployQueue.wake:
		}
		s.startPendingDeploy()
	}
}

// startPendingDeploy starts the oldest queued entry if the gate is free (it keeps its place otherwise).
// It reports whether one was started.
func (s *Server) startPendingDeploy() bool {
	// Intentional: take the gate before popping. Popping first and putting the entry back when the gate
	// is busy would let a PR-close remove() miss the entry in between and resurrect the preview. With an
	// empty queue the gate isn't touched at all (a deploy starting at that instant would get a 409).
	if s.deployQueue.empty() || !s.gitDeploy.TryAcquire() {
		return false
	}
	d, ok := s.deployQueue.pop()
	if !ok {
		s.gitDeploy.Release()
		return false
	}
	go func() {
		defer s.gitDeploy.Release()
		defer func() {
			if rec := recover(); rec != nil { // queued deploy work is driven by untrusted repo content
				s.log.Error("queued deploy panic recovered", "project", d.project, "pr", d.pr, "panic", rec)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), s.repoDeployTimeout())
		defer cancel()
		if s.queuedRun != nil { // test seam
			s.queuedRun(ctx, d)
			return
		}
		if d.source == queuedFromAPI {
			s.log.Info("running a queued API deploy", "project", d.project, "via", "api:"+d.tokenID, "waited", time.Since(d.queued).Round(time.Second))
			s.runQueuedAPIDeploy(ctx, d)
			return
		}
		s.log.Info("running a queued webhook", "project", d.project, "pr", d.pr, "waited", time.Since(d.queued).Round(time.Second))
		if d.pr == 0 {
			s.fetchAndMaybeDeploy(ctx, d.project, "webhook")
			return
		}
		// A preview: re-check that previews are still on for the base app (it may have changed while
		// the entry waited).
		if cfg, exists, _ := s.gitStore.Get(d.project); !exists || !cfg.PreviewEnabled {
			return
		}
		onLine := func(l string) { s.log.Info("preview", "base", d.project, "pr", d.pr, "line", l) }
		if err := s.createOrUpdatePreview(ctx, d.project, d.pr, onLine); err != nil {
			s.log.Warn("preview deploy failed", "base", d.project, "pr", d.pr, "err", err)
		}
	}()
	return true
}
