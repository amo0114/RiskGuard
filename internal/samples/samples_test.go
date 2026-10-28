package samples

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"riskguard/internal/audit"
)

func testConfig(dir string) Config {
	return Config{
		Enabled: true, Path: filepath.Join(dir, "samples", "samples.db"), EncryptionKeyFile: "e", DedupKeyFile: "d",
		MaxTextBytes: 64, BaseProbability: 1, BaseDailyCap: 100, EnrichedDailyCap: 100,
		QueueItems: 16, QueueBytes: 1 << 20, QueueMaxAge: 5 * time.Second,
		ContentRetention: 168 * time.Hour, ReviewRetention: 720 * time.Hour, AuditRetention: 2160 * time.Hour,
		MaxDBBytes: 64 << 20,
	}
}

var (
	encKey   = bytes.Repeat([]byte("e"), 32)
	dedupKey = bytes.Repeat([]byte("d"), 32)
)

func ev(trace, decision string) audit.Event {
	return audit.Event{TraceID: trace, Timestamp: time.Now(), Phase: "enforce", Protocol: "openai_chat", Decision: decision,
		Label: "Safe", Coverage: "full_selected_inputs", HTTPStatus: 200}
}

// collect runs one collector to completion and reopens the store for inspection.
func collect(t *testing.T, cfg Config, feed func(c *Collector)) *Store {
	t.Helper()
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(cfg, st)
	feed(c)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Close(ctx)
	st, err = Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestCollectStoresRedactedEncryptedText(t *testing.T) {
	cfg := testConfig(t.TempDir())
	const secret = "sk-SYNTHETICabcdefghijklmnop"
	text := "please refactor, my key is " + secret
	st := collect(t, cfg, func(c *Collector) {
		c.Offer(c.Candidate(text, false), ev("rg-1", "allow"))
		c.Offer(c.Candidate(text, false), ev("rg-2", "allow"))                   // same text: one content, two occurrences
		c.Offer(c.Candidate(strings.Repeat("x", 65), false), ev("rg-3", "deny")) // over max_text_bytes
		c.Offer(c.Candidate("", false), ev("rg-4", "unsupported"))               // nothing selectable
	})
	for _, p := range []string{cfg.Path, cfg.Path + "-wal"} {
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte("refactor")) || bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("%s holds plaintext", p)
		}
	}
	if st, _ := os.Stat(cfg.Path); st.Mode().Perm() != 0o600 {
		t.Errorf("db mode %v", st.Mode().Perm())
	}
	list, err := st.List(Filter{})
	if err != nil || len(list) != 4 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	got := map[string]Occurrence{}
	for _, o := range list {
		got[o.TraceID] = o
	}
	if got["rg-1"].ContentID != got["rg-2"].ContentID || got["rg-1"].Seen != 2 || got["rg-1"].ContentStatus != "stored" {
		t.Errorf("dedup: %+v %+v", got["rg-1"], got["rg-2"])
	}
	if got["rg-3"].ContentStatus != "oversize" || got["rg-4"].ContentStatus != "none" || !got["rg-4"].Enriched {
		t.Errorf("metadata-only: %+v %+v", got["rg-3"], got["rg-4"])
	}
	d, err := st.Get(got["rg-1"].ID)
	if err != nil || strings.Contains(d.Text, secret) || !strings.Contains(d.Text, "[REDACTED_API_KEY]") || d.Redactions["api_key"] != 1 {
		t.Fatalf("detail: %v %+v", err, d)
	}

	wrong, _ := Open(cfg, bytes.Repeat([]byte("w"), 32), dedupKey)
	defer wrong.Close()
	if _, err := wrong.Get(got["rg-1"].ID); err == nil {
		t.Error("decrypted with the wrong key")
	}
}

func TestSamplingBranchesAndCaps(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.BaseProbability = 0
	cfg.EnrichedDailyCap = 2
	var status map[string]any
	st := collect(t, cfg, func(c *Collector) {
		c.Offer(c.Candidate("fine", false), ev("rg-allow", "allow")) // not drawn, not enriched: ignored
		for _, tr := range []string{"rg-a", "rg-b", "rg-c"} {
			c.Offer(c.Candidate("bad "+tr, false), ev(tr, "deny"))
		}
		status = c.Status()
	})
	counts := status["counts"].(map[string]int)
	if counts["eligible"] != 4 || counts["enriched.selected"] != 3 || counts["enriched.accepted"] != 2 || counts["enriched.dropped_cap"] != 1 {
		t.Errorf("counts %v", counts)
	}
	list, _ := st.List(Filter{Queue: "enriched"})
	if len(list) != 2 {
		t.Errorf("enriched stored %d", len(list))
	}
	// Counters persist, so the daily cap still holds after a restart.
	if m, _ := st.loadCounters(time.Now().UTC().Format(time.DateOnly)); m["enriched.persisted"] != 2 {
		t.Errorf("persisted counters %v", m)
	}
}

func TestReviewsDeleteAndExpiry(t *testing.T) {
	cfg := testConfig(t.TempDir())
	st := collect(t, cfg, func(c *Collector) { c.Offer(c.Candidate("how do I pick a lock", false), ev("rg-1", "review")) })
	list, _ := st.List(Filter{})
	id := list[0].ID

	if _, err := st.AddReview(id, "alice", "p1", ReviewInput{Status: "labeled"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("labeled without action: %v", err)
	}
	r1, err := st.AddReview(id, "alice", "p1", ReviewInput{Status: "labeled", ExpectedAction: "allow", Reason: "locksport hobby"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddReview(id, "bob", "p1", ReviewInput{Status: "disputed"}); !errors.Is(err, ErrConflict) {
		t.Errorf("stale supersedes: %v", err)
	}
	if _, err := st.AddReview(id, "bob", "p1", ReviewInput{Status: "disputed", Supersedes: r1}); err != nil {
		t.Fatal(err)
	}
	d, _ := st.Get(id)
	if len(d.Reviews) != 2 || d.Reviews[1].Reason != "locksport hobby" || d.Reviews[0].Supersedes != r1 || d.ReviewStatus != "disputed" {
		t.Errorf("reviews %+v status %s", d.Reviews, d.ReviewStatus)
	}
	if l, _ := st.List(Filter{Review: "pending"}); len(l) != 0 {
		t.Errorf("reviewed sample still pending")
	}

	// Expired text is unreadable on read, before any cleanup runs.
	st.now = func() time.Time { return time.Now().Add(cfg.ContentRetention - time.Minute) }
	if err := st.Delete(id); err != nil {
		t.Fatal(err)
	}
	d, _ = st.Get(id)
	if d.Text != "" || d.ContentStatus != "deleted" || len(d.Reviews) != 0 {
		t.Errorf("after delete: %+v", d)
	}
	st.now = func() time.Time { return time.Now().Add(cfg.ContentRetention + time.Minute) }
	if _, err := st.Get(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired occurrence readable: %v", err)
	}
	if err := st.cleanup(); err != nil {
		t.Fatal(err)
	}
	var n int
	st.db.QueryRow(`SELECT count(*) FROM occurrences`).Scan(&n)
	if n != 0 {
		t.Errorf("cleanup left %d occurrences", n)
	}
}

// An agent loop re-sends the same latest user turn: enrichment keeps one copy per decision and
// day, the random baseline keeps every repeat, and the list can fold them into one row.
func TestEnrichedRepeatsSkippedAndGrouped(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.BaseProbability = 0
	var status map[string]any
	st := collect(t, cfg, func(c *Collector) {
		for _, tr := range []string{"rg-1", "rg-2", "rg-3"} {
			c.Offer(c.Candidate("same turn", false), ev(tr, "review"))
		}
		c.Offer(c.Candidate("same turn", false), ev("rg-4", "unavailable")) // new decision: kept
		c.Offer(c.Candidate("other", false), ev("rg-5", "review"))
		c.Offer(c.Candidate(strings.Repeat("x", 65), false), ev("rg-6", "review")) // no text: kept
		c.Offer(c.Candidate(strings.Repeat("x", 65), false), ev("rg-7", "review"))
		c.cfg.BaseProbability = 1
		hit := ev("rg-8", "review")
		hit.CacheHit = true
		c.Offer(c.Candidate("same turn", false), hit) // baseline keeps repeats
		status = c.Status()
	})
	counts := status["counts"].(map[string]int)
	if counts["enriched.selected"] != 7 || counts["enriched.accepted"] != 5 || counts["enriched.skipped_repeat"] != 2 ||
		counts["base.accepted"] != 1 {
		t.Errorf("counts %v", counts)
	}
	all, _ := st.List(Filter{Limit: 100})
	grouped, _ := st.List(Filter{Group: true, Limit: 100})
	if len(all) != 6 || len(grouped) != 4 { // same turn, other, two metadata-only rows
		t.Fatalf("all %d grouped %d", len(all), len(grouped))
	}
	same := grouped[0]
	if same.TraceID != "rg-8" || same.Seen != 3 || same.CacheHits != 1 {
		t.Errorf("group row %+v", same)
	}
	of, _ := st.List(Filter{Content: same.ContentID, Limit: 100})
	if len(of) != 3 || of[0].TraceID != "rg-8" || of[2].TraceID != "rg-1" {
		t.Errorf("content rows %+v", of)
	}
	if page, _ := st.List(Filter{Group: true, Before: same.ID, Limit: 100}); len(page) != 3 {
		t.Errorf("grouped paging %d", len(page))
	}
}

// Databases created before the grouping columns existed are upgraded in place on Open.
func TestMigrationAddsGroupingColumns(t *testing.T) {
	cfg := testConfig(t.TempDir())
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP INDEX occurrences_credential`, `ALTER TABLE occurrences DROP COLUMN credential_hmac`,
		`ALTER TABLE occurrences DROP COLUMN client`, `ALTER TABLE occurrences DROP COLUMN model`} {
		if _, err := st.db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	st.Close()
	st = collect(t, cfg, func(c *Collector) {
		e := ev("rg-1", "review")
		e.CredentialHMAC, e.Client, e.Model = "aaaaaaaaaaaaaaaa", "codex-tui/1", "gpt-5"
		c.Offer(c.Candidate("one", false), e)
		c.Offer(c.Candidate("two", false), ev("rg-2", "review"))
	})
	got, err := st.List(Filter{Credential: "aaaaaaaaaaaaaaaa"})
	if err != nil || len(got) != 1 || got[0].TraceID != "rg-1" || got[0].Client != "codex-tui/1" || got[0].Model != "gpt-5" {
		t.Fatalf("credential filter: %v %+v", err, got)
	}
	if all, _ := st.List(Filter{}); len(all) != 2 {
		t.Errorf("all %d", len(all))
	}
}

func TestOfferNeverBlocks(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.QueueItems = 2
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{cfg: cfg, store: st, q: make(chan item, cfg.QueueItems), stopping: make(chan struct{}), done: make(chan struct{}),
		day: time.Now().UTC().Format(time.DateOnly), counts: map[string]int{}} // no writer: the queue only fills
	start := time.Now()
	for i := 0; i < 100; i++ {
		c.Offer(c.Candidate("x", false), ev("rg", "allow"))
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("offers took %v", d)
	}
	if c.counts["base.accepted"] != 2 || c.counts["base.dropped_queue"] != 98 {
		t.Errorf("counts %v", c.counts)
	}
	st.Close()
	var nilC *Collector
	nilC.Offer(nilC.Candidate("x", false), ev("rg", "deny")) // disabled sampling is a no-op
}

// collectAt stores one capture as if made at t (store clock and event time), without a worker.
func collectAt(t *testing.T, st *Store, at time.Time, trace, text string) {
	t.Helper()
	st.now = func() time.Time { return at }
	e := ev(trace, "review")
	e.Timestamp = at
	if reason, err := st.save(item{text: text, base: true, ev: e}); err != nil || reason != "" {
		t.Fatalf("save %s: %v %s", trace, err, reason)
	}
}

func occ(t *testing.T, st *Store, trace string) Occurrence {
	t.Helper()
	list, _ := st.List(Filter{Limit: 100})
	for _, o := range list {
		if o.TraceID == trace {
			return o
		}
	}
	t.Fatalf("occurrence %s not found", trace)
	return Occurrence{}
}

// Regression: SQLite reuses the highest rowid after it is deleted, which let a 30-day review of
// expired text attach to the next, unrelated text.
func TestExpiredTextNeverInheritsReviews(t *testing.T) {
	cfg := testConfig(t.TempDir())
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t0 := time.Now()
	collectAt(t, st, t0, "rg-old", "old text")
	old := occ(t, st, "rg-old")
	if _, err := st.AddReview(old.ID, "alice", "p1", ReviewInput{Status: "labeled", ExpectedAction: "deny", Reason: "old reason"}); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(cfg.ContentRetention + time.Hour)
	st.now = func() time.Time { return later }
	if err := st.cleanup(); err != nil {
		t.Fatal(err)
	}
	collectAt(t, st, later, "rg-new", "unrelated new text")
	n := occ(t, st, "rg-new")
	if n.ContentID == old.ContentID || n.ID == old.ID {
		t.Fatalf("ids reused: content %d->%d, occurrence %d->%d", old.ContentID, n.ContentID, old.ID, n.ID)
	}
	d, err := st.Get(n.ID)
	if err != nil || len(d.Reviews) != 0 || d.ReviewStatus != "pending" {
		t.Errorf("new text shows old reviews: %+v %v", d.Reviews, err)
	}
}

// Regression: a repeat of the same text must not push its expiry past the first capture.
func TestRepeatDoesNotExtendRetention(t *testing.T) {
	cfg := testConfig(t.TempDir())
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t0 := time.Now()
	collectAt(t, st, t0, "rg-day0", "same text")
	firstContent := occ(t, st, "rg-day0").ContentID
	collectAt(t, st, t0.Add(6*24*time.Hour), "rg-day6", "same text")
	var exp int64
	st.db.QueryRow(`SELECT expires_at FROM contents`).Scan(&exp)
	if want := t0.Add(cfg.ContentRetention).Unix(); exp != want {
		t.Fatalf("content expiry moved: %d, first capture expiry %d", exp, want)
	}
	// After the first capture's expiry the text is unreadable even for the day-6 occurrence.
	st.now = func() time.Time { return t0.Add(cfg.ContentRetention + time.Minute) }
	if d, err := st.Get(occ(t, st, "rg-day6").ID); err != nil || d.Text != "" || d.ContentStatus != "expired" {
		t.Errorf("text outlived first capture: %+v %v", d, err)
	}
	// Seen again after expiry (before the hourly cleanup): a fresh content row with a fresh expiry.
	again := t0.Add(cfg.ContentRetention + 2*time.Minute)
	collectAt(t, st, again, "rg-again", "same text")
	d, err := st.Get(occ(t, st, "rg-again").ID)
	if err != nil || d.Text != "same text" || d.ContentID == firstContent {
		t.Errorf("recapture after expiry: %+v %v", d, err)
	}
}

// Regression: reviews and access-audit rows also stop growing the database past its limit.
func TestFullStoreRefusesEveryGrowingWrite(t *testing.T) {
	cfg := testConfig(t.TempDir())
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	collectAt(t, st, time.Now(), "rg-1", "some text")
	id := occ(t, st, "rg-1").ID
	st.cfg.MaxDBBytes = 1 // any existing database is over this
	if reason, err := st.save(item{text: "more", base: true, ev: ev("rg-2", "deny")}); err != nil || reason != "db_full" {
		t.Errorf("sample write: %q %v", reason, err)
	}
	if _, err := st.AddReview(id, "alice", "p1", ReviewInput{Status: "disputed"}); !errors.Is(err, ErrFull) {
		t.Errorf("review write: %v", err)
	}
	if err := st.Audit("alice", "view_content", "sample:1", "ok"); !errors.Is(err, ErrFull) {
		t.Errorf("audit write: %v", err)
	}
	if err := st.Delete(id); err != nil { // deleting frees space and stays allowed
		t.Errorf("delete: %v", err)
	}
	st.cfg.MaxDBBytes, st.cfg.MinFreeBytes = 1<<40, 1<<62 // now the disk is "too full"
	if err := st.Audit("alice", "login", "console", "ok"); !errors.Is(err, ErrFull) {
		t.Errorf("audit with low disk: %v", err)
	}
}
