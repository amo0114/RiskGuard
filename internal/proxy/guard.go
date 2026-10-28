package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"riskguard/internal/audit"
	"riskguard/internal/classifier"
	"riskguard/internal/extract"
	"riskguard/internal/limits"
	"riskguard/internal/policy"
	"riskguard/internal/routes"
	"riskguard/internal/samples"
)

// Guard holds the inspection pipeline. All budgets are independent of New API's user limits: they
// only protect this host and the remote classifier from pre-auth abuse.
type Guard struct {
	Policy            *policy.Policy
	Classifier        classifier.Classifier
	ModelID           string // configured classifier model name, part of the cache key
	Spool             *SpoolPool
	Budget            extract.Budget
	ExtractGate       *limits.Gate
	ClassifierGate    *limits.Gate
	QueueWait         time.Duration
	ClassifierTimeout time.Duration
	AttemptTimeout    time.Duration // 0: one attempt per classification; see classify
	PerIP             *limits.KeyedRate
	PerCredential     *limits.KeyedRate
	Cache             *Cache
	Fingerprint       func(string) string
	// Judge, when set, is asked in shadow mode only; see askJudge.
	Judge        *classifier.Judge
	JudgeGate    *limits.Gate
	JudgeTimeout time.Duration
	// BlockReplyOn is the console switch for answering content rejections with
	// Policy.Enforce.BlockReplies; off keeps the 4xx errors.
	BlockReplyOn atomic.Bool
	replies      replyBag

	mu         sync.Mutex
	lastOK     time.Time
	lastFail   time.Time
	lastStatus string
}

// guarded handles inspectable routes. It registers shadow work before forwarding so
// an aborted upstream response cannot detach that work from audit draining.
func (h *Handler) guarded(rec *recorder, r *http.Request, rt routes.Result, ev *audit.Event, pending *<-chan struct{}, cand **samples.Candidate) {
	g := h.guard
	trace := ev.TraceID

	if rt.Class == routes.ModelUninspectable || rt.Class == routes.Unknown {
		ev.Coverage = "unsupported"
		d := policy.Decision{Decision: policy.Unsupported, Reason: "COVERAGE_GAP"}
		if g.Policy.Excepted(rt.Protocol, rt.Template) {
			d.Reason = "APPROVED_EXCEPTION"
			h.decide(rec, r, rt, ev, d, policy.Action{Forward: true}, nil)
			return
		}
		h.decide(rec, r, rt, ev, d, g.Policy.Action(d), nil)
		return
	}

	// model_text from here on
	if g.Policy.T0Only(rt.Protocol) {
		ev.Coverage = "t0_only"
		h.decide(rec, r, rt, ev, policy.Decision{Decision: policy.Allow, Reason: "T0_ONLY_EXCEPTION"}, policy.Action{Forward: true}, nil)
		return
	}

	ipKey := g.Fingerprint("ip:" + r.Header.Get("X-Real-IP"))
	credKey := g.Fingerprint("cred:" + credential(r))
	if !g.PerIP.Allow(ipKey) || !g.PerCredential.Allow(credKey) {
		d := policy.Decision{Decision: policy.Unavailable, Reason: "ADMISSION_LIMIT"}
		h.decide(rec, r, rt, ev, d, policy.Action{Status: http.StatusTooManyRequests, Code: "RATE_LIMITED", Message: "too many requests for content review"}, nil)
		return
	}

	sp, err := g.Spool.Read(http.MaxBytesReader(rec, r.Body, h.maxBody))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		ev.Decision, ev.ReasonCode = "reject", "BODY_TOO_LARGE"
		writeError(rec, rt.Protocol, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body too large", trace)
		return
	case errors.Is(err, ErrSpoolFull):
		defer sp.Close()
		d := policy.Decision{Decision: policy.Unavailable, Reason: "SPOOL_FULL"}
		h.decide(rec, r, rt, ev, d, policy.Action{Status: http.StatusServiceUnavailable, Code: "GUARD_UNAVAILABLE", Message: "content guard busy"}, sp)
		return
	case errors.Is(err, ErrSpoolIO):
		// The buffered prefix was discarded; shadow cannot safely forward the remainder.
		ev.Decision, ev.ReasonCode = policy.Unavailable, "SPOOL_IO_FAILED"
		writeError(rec, rt.Protocol, http.StatusServiceUnavailable, "GUARD_UNAVAILABLE", "content guard storage unavailable", trace)
		return
	case err != nil:
		if r.Context().Err() != nil {
			ev.Decision, ev.ReasonCode = "aborted", "BODY_READ_FAILED"
			rec.status = 499
			return
		}
		ev.Decision, ev.ReasonCode = "reject", "BODY_READ_FAILED"
		writeError(rec, rt.Protocol, http.StatusBadRequest, "BODY_READ_FAILED", "could not read request body", trace)
		return
	}
	defer sp.Close()

	wait := g.QueueWait
	if h.mode != "enforce" {
		wait = 0 // shadow skips inspection immediately when extraction is saturated
	}
	release, err := g.ExtractGate.Acquire(r.Context(), wait)
	if err != nil {
		d := policy.Decision{Decision: policy.Unavailable, Reason: "EXTRACT_BUSY"}
		h.decide(rec, r, rt, ev, d, policy.Action{Status: http.StatusServiceUnavailable, Code: "GUARD_UNAVAILABLE", Message: "content guard busy"}, sp)
		return
	}
	inspected := &spoolInspectionReader{Reader: sp.Reader()}
	sel := extract.Extract(rt.Protocol, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), inspected, g.Budget, h.maxBody)
	release()
	if inspected.err != nil {
		ev.Decision, ev.ReasonCode = policy.Unavailable, "SPOOL_IO_FAILED"
		writeError(rec, rt.Protocol, http.StatusServiceUnavailable, "GUARD_UNAVAILABLE", "content guard storage unavailable", trace)
		return
	}
	ev.Coverage, ev.InspectedChars = string(sel.Coverage), sel.InspectedChars
	ev.Model = modelOf(sel.Model, r.URL.Path)
	if h.samples != nil { // only the classifier input itself may be sampled, never the body or spool
		*cand = h.samples.Candidate(sel.Text(), sel.Truncated)
	}
	if sel.Coverage == extract.Unsupported {
		d := policy.Decision{Decision: policy.Unsupported, Reason: sel.Reason}
		h.decide(rec, r, rt, ev, d, g.Policy.Action(d), sp)
		return
	}
	if sel.Reason != "" {
		ev.CoverageReason = sel.Reason
	}

	if h.mode != "enforce" {
		// Shadow: never delay or alter the request. Classify concurrently and log once both finish.
		done := make(chan struct{})
		*pending = done // register before forwarding, including upstream abort/panic paths
		text := sel.Text()
		go func() {
			defer close(done)
			if g.Judge != nil {
				judged := make(chan struct{})
				go func() { defer close(judged); g.askJudge(h.shadowCtx, text, ev) }()
				defer func() { <-judged }()
			}
			ctx, cancel := context.WithTimeout(h.shadowCtx, g.ClassifierTimeout)
			defer cancel()
			res, hit := g.classify(ctx, text, 0)
			recordClassification(ev, res, hit)
			d := g.Policy.Classified(res)
			ev.Decision, ev.ReasonCode = d.Decision, d.Reason
			ev.WouldBlock = !g.Policy.Action(d).Forward
			if h.shadowCtx.Err() != nil {
				ev.ClassifierStatus = "cancelled"
				ev.Decision, ev.ReasonCode = policy.Unavailable, "SHUTDOWN_CANCELLED"
				ev.WouldBlock = true
			}
		}()
		h.forward(rec, r, ev, sp.Forward())
		return
	}

	res, hit := g.classify(r.Context(), sel.Text(), g.QueueWait)
	recordClassification(ev, res, hit)
	d := g.Policy.Classified(res)
	h.decide(rec, r, rt, ev, d, g.Policy.Action(d), sp)
	return
}

// decide records d and, in enforce mode, applies a; shadow mode always forwards.
func (h *Handler) decide(rec *recorder, r *http.Request, rt routes.Result, ev *audit.Event, d policy.Decision, a policy.Action, sp *Spool) {
	ev.Decision, ev.ReasonCode = d.Decision, d.Reason
	forward := func() {
		if sp != nil {
			h.forward(rec, r, ev, sp.Forward())
		} else {
			h.forward(rec, r, ev, nil)
		}
	}
	if h.mode != "enforce" {
		ev.WouldBlock = !a.Forward
		forward()
		return
	}
	if a.Forward {
		forward()
		return
	}
	ev.Enforced = true
	// Only content verdicts get the friendly reply; outages and coverage gaps stay visible errors.
	g, replies := h.guard, h.guard.Policy.Enforce.BlockReplies
	if sp != nil && g.BlockReplyOn.Load() && len(replies) > 0 && (d.Decision == policy.Deny || d.Decision == policy.Review) &&
		canFakeReply(rt.Protocol) && writeBlockReply(r, rec, rt.Protocol, sp.Reader(), replies[g.replies.next(len(replies))], a.Code, ev.TraceID) {
		return
	}
	writeError(rec, rt.Protocol, a.Status, a.Code, a.Message, ev.TraceID)
}

func recordClassification(ev *audit.Event, res classifier.Result, hit bool) {
	ev.Label = res.Label
	ev.Categories = res.Categories
	ev.Classifier = res.ModelID
	ev.ClassifierStatus = res.Status
	ev.ClassifierMS = res.Duration.Milliseconds()
	ev.ClassifierRetried = res.Retried
	ev.CacheHit = hit
}

// classify makes at most one classifier call per request; wait bounds the queue time.
func (g *Guard) classify(ctx context.Context, text string, wait time.Duration) (classifier.Result, bool) {
	key := g.cacheKey(text)
	if res, ok := g.Cache.Get(key); ok {
		return res, true
	}
	release, err := g.ClassifierGate.Acquire(ctx, wait)
	if err != nil {
		return classifier.Result{Label: classifier.Unknown, ModelID: g.ModelID, Status: "busy"}, false
	}
	defer release()
	cctx, cancel := context.WithTimeout(ctx, g.ClassifierTimeout)
	defer cancel()
	// The remote classifier occasionally stalls one call while the next is answered in ~2s. With an
	// attempt timeout, a hang, connection failure or 5xx is retried once inside the same overall
	// timeout, so what an enforce request can wait is unchanged. Answers (incl. 4xx, parse
	// failures) are never retried.
	res := g.attempt(cctx, text)
	if g.AttemptTimeout > 0 && retryable(res.Status) && ctx.Err() == nil {
		if dl, _ := cctx.Deadline(); time.Until(dl) >= time.Second {
			first := res.Duration
			res = g.attempt(cctx, text)
			res.Duration += first
			res.Retried = true
		}
	}
	g.mu.Lock()
	if res.Status == "ok" || res.Status == "parse_failed" {
		g.lastOK = time.Now()
	} else {
		g.lastFail, g.lastStatus = time.Now(), res.Status
	}
	g.mu.Unlock()
	if res.Status == "ok" {
		g.Cache.Put(key, res)
	}
	return res, false
}

func (g *Guard) attempt(ctx context.Context, text string) classifier.Result {
	if g.AttemptTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.AttemptTimeout)
		defer cancel()
	}
	return g.Classifier.Moderate(ctx, text)
}

func retryable(status string) bool {
	return status == "timeout" || status == "unavailable" || strings.HasPrefix(status, "http_5")
}

// askJudge records the auxiliary judge's probabilities on ev (Aux* fields only). It never waits
// for a slot: when the judge is saturated the event just says so.
func (g *Guard) askJudge(parent context.Context, text string, ev *audit.Event) {
	release, err := g.JudgeGate.Acquire(parent, 0)
	if err != nil {
		ev.AuxStatus = "busy"
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(parent, g.JudgeTimeout)
	defer cancel()
	a := g.Judge.Ask(ctx, text)
	ev.AuxModel, ev.AuxStatus, ev.AuxMS = a.Model, a.Status, a.Duration.Milliseconds()
	if parent.Err() != nil {
		ev.AuxStatus = "cancelled"
	}
	if a.Probs != nil {
		ev.Aux = make(map[string]float64, len(a.Probs))
		for k, p := range a.Probs {
			ev.Aux[k] = math.Round(p*1000) / 1000
		}
	}
}

func (g *Guard) cacheKey(text string) string {
	sum := sha256.Sum256([]byte(g.ModelID + "\x00" + text))
	return hex.EncodeToString(sum[:])
}

// ClassifierHealth is reported on the admin listener; it never affects readiness, so a remote
// classifier outage cannot cause restart loops.
func (g *Guard) ClassifierHealth() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	inUse, waiting := g.ClassifierGate.InUse()
	spoolBytes, spoolFiles := g.Spool.Usage()
	spoolMemory, spoolMemoryLimit := g.Spool.MemoryUsage()
	return map[string]any{
		"last_ok": g.lastOK, "last_failure": g.lastFail, "last_failure_status": g.lastStatus,
		"in_flight": inUse, "waiting": waiting, "spool_bytes": spoolBytes, "spool_files": spoolFiles,
		"spool_memory_bytes": spoolMemory, "spool_max_memory_bytes": spoolMemoryLimit,
	}
}

// credential returns the raw client credential for pre-auth budgeting only. It is HMAC'd before
// use and never treated as an identity; New API alone validates it.
func credential(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		return strings.TrimPrefix(v, "Bearer ")
	}
	for _, h := range []string{"X-Api-Key", "X-Goog-Api-Key", "Mj-Api-Secret"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	if v := r.URL.Query().Get("key"); v != "" {
		return v
	}
	for _, p := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if p = strings.TrimSpace(p); strings.HasPrefix(p, "openai-insecure-api-key.") {
			return strings.TrimPrefix(p, "openai-insecure-api-key.")
		}
	}
	return ""
}

// Cache remembers classifier results (never text) by content hash. Agent loops resend the same
// latest user turn with every tool step; this keeps them to one classifier call.
type Cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]cacheEntry
	order   []string
}

type cacheEntry struct {
	res classifier.Result
	exp time.Time
}

func NewCache(ttl time.Duration, max int) *Cache {
	return &Cache{ttl: ttl, max: max, entries: map[string]cacheEntry{}}
}

func (c *Cache) Get(k string) (classifier.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || time.Now().After(e.exp) {
		return classifier.Result{}, false
	}
	return e.res, true
}

func (c *Cache) Put(k string, r classifier.Result) {
	if c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[k]; !ok {
		for len(c.order) >= c.max {
			delete(c.entries, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, k)
	}
	c.entries[k] = cacheEntry{res: r, exp: time.Now().Add(c.ttl)}
}
