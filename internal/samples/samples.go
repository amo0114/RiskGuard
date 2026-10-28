// Package samples keeps a short-lived, redacted and encrypted copy of the text the classifier
// actually inspected, for a bounded sample of requests, plus human reviews of it. It is off by
// default and stays off the request path: the proxy hands over an immutable copy without waiting,
// and a collection failure only stops collection, never changes a Guard decision.
package samples

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"riskguard/internal/audit"
)

type Config struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"sqlite_path"`
	// Key files hold >=32 random bytes; they must differ from every other secret.
	EncryptionKeyFile string `yaml:"encryption_key_file"`
	DedupKeyFile      string `yaml:"dedup_key_file"`
	// MaxTextBytes caps what is stored; longer inspected text keeps only metadata (never re-cut).
	MaxTextBytes int `yaml:"max_text_bytes"`
	// BaseProbability draws the random baseline before the classifier answers, so it also shows
	// what the classifier let through. review/deny/unavailable/unsupported are always offered.
	BaseProbability  float64       `yaml:"base_probability"`
	BaseDailyCap     int           `yaml:"base_daily_cap"`
	EnrichedDailyCap int           `yaml:"enriched_daily_cap"`
	QueueItems       int           `yaml:"queue_items"`
	QueueBytes       int64         `yaml:"queue_bytes"`
	QueueMaxAge      time.Duration `yaml:"queue_max_age"`
	ContentRetention time.Duration `yaml:"content_retention"`
	ReviewRetention  time.Duration `yaml:"review_retention"`
	AuditRetention   time.Duration `yaml:"audit_retention"`
	MaxDBBytes       int64         `yaml:"max_db_bytes"`
	MinFreeBytes     int64         `yaml:"min_free_bytes"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch {
	case c.Path == "" || c.EncryptionKeyFile == "" || c.DedupKeyFile == "":
		return errors.New("samples: sqlite_path, encryption_key_file and dedup_key_file are required")
	case c.EncryptionKeyFile == c.DedupKeyFile:
		return errors.New("samples: encryption and dedup keys must be different files")
	case c.MaxTextBytes <= 0 || c.MaxTextBytes > 16<<10:
		return errors.New("samples: max_text_bytes must be 1..16384")
	case c.BaseProbability < 0 || c.BaseProbability > 1:
		return errors.New("samples: base_probability must be 0..1")
	case c.BaseDailyCap <= 0 || c.EnrichedDailyCap <= 0 || c.QueueItems < 2 || c.QueueBytes <= 0 || c.QueueMaxAge <= 0:
		return errors.New("samples: caps, queue_items (>=2), queue_bytes and queue_max_age must be positive")
	case c.ContentRetention <= 0 || c.ReviewRetention <= 0 || c.AuditRetention <= 0:
		return errors.New("samples: retention periods must be positive")
	case c.MaxDBBytes <= 0 || c.MinFreeBytes < 0:
		return errors.New("samples: max_db_bytes must be positive and min_free_bytes non-negative")
	}
	return nil
}

// sampling is stored with every occurrence so a later report knows the plan it was drawn under.
func (c Config) sampling() string {
	return fmt.Sprintf("v1 p=%g base_cap=%d enriched_cap=%d", c.BaseProbability, c.BaseDailyCap, c.EnrichedDailyCap)
}

// Candidate is drawn once the inspected text is known. Text is the classifier input itself (an
// immutable string), never the request body or spool.
type Candidate struct {
	text      string
	oversize  bool
	truncated bool
	base      bool
}

type item struct {
	text                string
	oversize, truncated bool
	base, enriched      bool
	ev                  audit.Event
	queued              time.Time
	size                int64
}

// Collector owns the bounded queue and the single writer goroutine. All methods are nil-safe so
// the proxy needs no checks when sampling is disabled.
type Collector struct {
	cfg   Config
	store *Store
	q     chan item

	mu       sync.Mutex
	closed   bool
	qBytes   int64
	day      string
	counts   map[string]int
	finished []dayCounts // days rolled over but not yet saved
	// repeats holds today's accepted enriched (decision, text) pairs. An agent loop re-sends the
	// same latest user turn on every tool round; without this one review-worthy sentence would
	// spend the enriched cap. In memory only (seeded hash, no oracle), so a restart may enrich
	// one more copy; bounded by the enriched cap since only accepted pairs are added.
	repeats  map[uint64]struct{}
	seed     maphash.Seed
	lastErr  string
	stopping chan struct{}
	done     chan struct{}
}

type dayCounts struct {
	day    string
	counts map[string]int
}

// NewCollector resumes today's counters (daily caps survive restarts) and starts the writer.
func NewCollector(cfg Config, store *Store) *Collector {
	c := &Collector{cfg: cfg, store: store, q: make(chan item, cfg.QueueItems), stopping: make(chan struct{}), done: make(chan struct{})}
	c.day = time.Now().UTC().Format(time.DateOnly)
	m, err := store.loadCounters(c.day)
	if err != nil {
		c.lastErr = "counters: " + err.Error()
		m = map[string]int{}
	}
	c.counts = m
	go c.run()
	return c
}

// rollDay starts a new UTC day's counters. Caller holds mu; it does no I/O, so the request path
// never waits on SQLite.
func (c *Collector) rollDay(now time.Time) {
	day := now.UTC().Format(time.DateOnly)
	if day == c.day {
		return
	}
	c.finished = append(c.finished, dayCounts{c.day, c.counts})
	c.day, c.counts, c.repeats = day, map[string]int{}, nil
}

// flush saves counters; only the writer goroutine (or Close after it exits) calls it.
func (c *Collector) flush() {
	c.mu.Lock()
	c.rollDay(time.Now())
	batch := append(c.finished, dayCounts{c.day, make(map[string]int, len(c.counts))})
	for k, v := range c.counts {
		batch[len(batch)-1].counts[k] = v
	}
	c.finished = nil
	c.mu.Unlock()
	for _, d := range batch {
		if err := c.store.saveCounters(d.day, d.counts); err != nil {
			c.setErr("counters", err)
		}
	}
}

func (c *Collector) count(key string) {
	c.mu.Lock()
	c.rollDay(time.Now())
	c.counts[key]++
	c.mu.Unlock()
}

// Candidate draws the random baseline for a request whose inspected text is known.
func (c *Collector) Candidate(text string, truncated bool) *Candidate {
	if c == nil {
		return nil
	}
	cand := &Candidate{truncated: truncated, base: rand.Float64() < c.cfg.BaseProbability}
	if len(text) > c.cfg.MaxTextBytes {
		cand.oversize = true
	} else {
		cand.text = text
	}
	c.count("eligible")
	return cand
}

var enrichedDecisions = []string{"review", "deny", "unavailable", "unsupported"}

// Offer queues the candidate with its final, already-written audit event (a copy, so nothing is
// shared with request goroutines). It never blocks: a full queue or spent cap drops the sample.
func (c *Collector) Offer(cand *Candidate, ev audit.Event) {
	if c == nil || cand == nil {
		return
	}
	enriched := oneOf(ev.Decision, enrichedDecisions...)
	if !cand.base && !enriched {
		return
	}
	// The random baseline is the statistical sample; an item in it counts there even if enriched.
	queue, limit := "base", c.cfg.BaseDailyCap
	if !cand.base {
		queue, limit = "enriched", c.cfg.EnrichedDailyCap
	}
	it := item{text: cand.text, oversize: cand.oversize, truncated: cand.truncated, base: cand.base, enriched: enriched,
		ev: ev, queued: time.Now(), size: int64(len(cand.text)) + 512}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollDay(it.queued)
	c.counts[queue+".selected"]++
	// The random baseline keeps every repeat; only enrichment skips text it already took today.
	var key uint64
	if queue == "enriched" && it.text != "" {
		if c.repeats == nil {
			c.repeats, c.seed = map[uint64]struct{}{}, maphash.MakeSeed()
		}
		key = maphash.String(c.seed, ev.Decision+"\x00"+it.text)
		if _, ok := c.repeats[key]; ok {
			c.counts[queue+".skipped_repeat"]++
			return
		}
	}
	// Enriched items may use only half the queue, so a flood of blocked requests cannot crowd out
	// the random baseline.
	maxItems, maxBytes := c.cfg.QueueItems, c.cfg.QueueBytes
	if queue == "enriched" {
		maxItems, maxBytes = maxItems/2, maxBytes/2
	}
	switch {
	case c.closed:
		c.counts[queue+".dropped_shutdown"]++
	case c.counts[queue+".accepted"] >= limit:
		c.counts[queue+".dropped_cap"]++
	case len(c.q) >= maxItems || c.qBytes+it.size > maxBytes:
		c.counts[queue+".dropped_queue"]++
	default:
		select {
		case c.q <- it:
			c.qBytes += it.size
			c.counts[queue+".accepted"]++
			if key != 0 {
				c.repeats[key] = struct{}{}
			}
		default:
			c.counts[queue+".dropped_queue"]++
		}
	}
}

func (c *Collector) run() {
	defer close(c.done)
	flush := time.NewTicker(time.Minute)
	clean := time.NewTicker(time.Hour)
	defer flush.Stop()
	defer clean.Stop()
	if err := c.store.cleanup(); err != nil {
		c.setErr("cleanup", err)
	}
	for {
		select {
		case it, ok := <-c.q:
			if !ok {
				return
			}
			c.store1(it)
		case <-flush.C:
			c.flush()
		case <-clean.C:
			if err := c.store.cleanup(); err != nil {
				c.setErr("cleanup", err)
			}
		}
	}
}

func (c *Collector) store1(it item) {
	queue := "base"
	if !it.base {
		queue = "enriched"
	}
	c.mu.Lock()
	c.qBytes -= it.size
	c.mu.Unlock()
	select {
	case <-c.stopping:
		c.count(queue + ".dropped_shutdown")
		return
	default:
	}
	if time.Since(it.queued) > c.cfg.QueueMaxAge {
		c.count(queue + ".dropped_stale")
		return
	}
	reason, err := c.store.save(it)
	switch {
	case err != nil:
		c.setErr("save", err)
		c.count(queue + ".dropped_error")
	case reason != "":
		c.count(queue + ".dropped_" + reason)
	default:
		c.count(queue + ".persisted")
	}
}

func (c *Collector) setErr(op string, err error) {
	log.Printf("riskguard: samples %s: %v", op, err)
	c.mu.Lock()
	c.lastErr = op + ": " + err.Error()
	c.mu.Unlock()
}

// Close stops accepting samples, stores what is queued until ctx ends (the rest is counted as
// dropped), saves the counters and closes the database.
func (c *Collector) Close(ctx context.Context) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	close(c.q)
	c.mu.Unlock()
	select {
	case <-c.done:
	case <-ctx.Done():
		close(c.stopping)
		<-c.done
	}
	c.flush()
	c.store.Close()
}

// Status is shown on the console; it carries counts and sizes, never text.
func (c *Collector) Status() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollDay(time.Now())
	counts := make(map[string]int, len(c.counts))
	for k, v := range c.counts {
		counts[k] = v
	}
	return map[string]any{
		"enabled": true, "day": c.day, "counts": counts, "last_error": c.lastErr,
		"queue_items": len(c.q), "queue_bytes": c.qBytes, "queue_max_items": c.cfg.QueueItems, "queue_max_bytes": c.cfg.QueueBytes,
		"db_bytes": c.store.dbBytes(), "max_db_bytes": c.cfg.MaxDBBytes, "free_bytes": c.store.freeBytes(), "min_free_bytes": c.cfg.MinFreeBytes,
		"base_probability": c.cfg.BaseProbability, "base_daily_cap": c.cfg.BaseDailyCap, "enriched_daily_cap": c.cfg.EnrichedDailyCap,
		"max_text_bytes": c.cfg.MaxTextBytes, "content_retention_hours": c.cfg.ContentRetention.Hours(),
		"review_retention_hours": c.cfg.ReviewRetention.Hours(), "redaction_version": redactionVersion,
	}
}

func (c *Collector) Store() *Store { return c.store }
