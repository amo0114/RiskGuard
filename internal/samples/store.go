package samples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite" // pure Go: keeps the static CGO-free build

	"riskguard/internal/classifier"
)

// AUTOINCREMENT on every id: plain rowids are reused after the highest row is deleted, and
// reviews (kept longer than text) and access-audit objects must never point at a newer sample.
const schema = `
CREATE TABLE IF NOT EXISTS contents (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	hmac TEXT NOT NULL UNIQUE,      -- keyed HMAC of the inspected text: dedup without a dictionary oracle
	status TEXT NOT NULL,           -- stored | excluded
	exclude_reason TEXT,
	key_id TEXT, nonce BLOB, ciphertext BLOB,
	text_bytes INTEGER NOT NULL,
	redactions TEXT NOT NULL,       -- {"kind": count}; never the removed strings
	redaction_version INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS occurrences (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_id TEXT NOT NULL UNIQUE,
	content_id INTEGER REFERENCES contents(id) ON DELETE SET NULL,
	content_status TEXT NOT NULL,   -- stored | excluded | oversize | none | deleted | expired
	ts INTEGER NOT NULL,
	phase TEXT NOT NULL, protocol TEXT NOT NULL, path_template TEXT NOT NULL,
	coverage TEXT NOT NULL, coverage_reason TEXT NOT NULL, inspected_chars INTEGER NOT NULL, truncated INTEGER NOT NULL,
	base INTEGER NOT NULL, enriched INTEGER NOT NULL, sampling TEXT NOT NULL,
	decision TEXT NOT NULL, reason_code TEXT NOT NULL, label TEXT NOT NULL, categories TEXT NOT NULL,
	classifier TEXT NOT NULL, classifier_status TEXT NOT NULL, classifier_ms INTEGER NOT NULL, cache_hit INTEGER NOT NULL,
	policy_version TEXT NOT NULL, enforced INTEGER NOT NULL, would_block INTEGER NOT NULL,
	http_status INTEGER NOT NULL, client_aborted INTEGER NOT NULL, latency_ms INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	credential_hmac TEXT NOT NULL DEFAULT '', client TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS occurrences_content ON occurrences(content_id);
CREATE TABLE IF NOT EXISTS reviews (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	content_id INTEGER NOT NULL,    -- no FK: labels outlive the 7-day text (datasets use them later)
	actor TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	policy_version TEXT NOT NULL,
	status TEXT NOT NULL,           -- labeled | insufficient_context | disputed | excluded_sensitive
	expected_action TEXT NOT NULL,  -- allow | review | deny, empty unless labeled
	category TEXT NOT NULL,
	reason_nonce BLOB, reason_ct BLOB,
	supersedes INTEGER,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS reviews_content ON reviews(content_id);
CREATE TABLE IF NOT EXISTS access_audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
	object TEXT NOT NULL, result TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (day TEXT NOT NULL, key TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, key));
`

var (
	ErrFull     = errors.New("sample store is over its size or free-disk limit")
	ErrNotFound = errors.New("sample not found")
	ErrConflict = errors.New("review changed since it was loaded")
	ErrInvalid  = errors.New("invalid review")
)

// Store is the sample database. The collector worker is its only bulk writer; console requests
// add reviews, deletions and access-audit rows.
type Store struct {
	db    *sql.DB
	path  string
	cfg   Config
	aead  cipher.AEAD
	keyID string
	dedup []byte
	now   func() time.Time
}

// Open creates the directory (0700) and database (0600) if needed. Text and review reasons are
// sealed with AES-256-GCM under a key derived from encKey; dedupKey keys the content HMAC.
func Open(cfg Config, encKey, dedupKey []byte) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, err
	}
	// SQLite gives -wal/-shm the database file's mode, so creating it 0600 covers all three.
	f, err := os.OpenFile(cfg.Path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	dsn := "file:" + cfg.Path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	k := sha256.Sum256(encKey)
	block, _ := aes.NewCipher(k[:])
	aead, _ := cipher.NewGCM(block)
	id := sha256.Sum256(append([]byte("riskguard-sample-key-id:"), k[:]...))
	return &Store{db: db, path: cfg.Path, cfg: cfg, aead: aead, keyID: hex.EncodeToString(id[:4]), dedup: dedupKey, now: time.Now}, nil
}

// addedColumns were added after the first release; databases created before get them here.
var addedColumns = []string{"credential_hmac", "client", "model"}

func migrate(db *sql.DB) error {
	rows, err := db.Query(`SELECT name FROM pragma_table_info('occurrences')`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		have[n] = true
	}
	rows.Close()
	for _, c := range addedColumns {
		if !have[c] {
			if _, err := db.Exec(`ALTER TABLE occurrences ADD COLUMN ` + c + ` TEXT NOT NULL DEFAULT ''`); err != nil {
				return err
			}
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS occurrences_credential ON occurrences(credential_hmac)`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) seal(aad, plain string) (nonce, ct []byte) {
	nonce = make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return nonce, s.aead.Seal(nil, nonce, []byte(plain), []byte(aad))
}

func (s *Store) open(aad string, nonce, ct []byte) (string, error) {
	p, err := s.aead.Open(nil, nonce, ct, []byte(aad))
	return string(p), err
}

// dbBytes is the main file plus WAL: what the size budget limits.
func (s *Store) dbBytes() int64 {
	var n int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		if st, err := os.Stat(p); err == nil {
			n += st.Size()
		}
	}
	return n
}

func (s *Store) freeBytes() int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(filepath.Dir(s.path), &st) != nil {
		return -1
	}
	return int64(st.Bavail) * st.Bsize
}

// full reports why the database must not grow: past max_db_bytes or below min_free_bytes. Every
// growing write checks it (samples, reviews, access audit). Deletes and expiry cleanup are always
// allowed, and the daily counters are exempt: at most a few dozen keys per day, pruned with the
// access audit, and caps must keep holding when the store is full.
func (s *Store) full() string {
	if s.dbBytes() >= s.cfg.MaxDBBytes {
		return "db_full"
	}
	if free := s.freeBytes(); free >= 0 && free < s.cfg.MinFreeBytes {
		return "disk_low"
	}
	return ""
}

// save stores one item. A non-empty reason means it was dropped before any write.
func (s *Store) save(it item) (reason string, err error) {
	if r := s.full(); r != "" {
		return r, nil
	}
	now := s.now()
	exp := now.Add(s.cfg.ContentRetention).Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	status := "none"
	var contentID sql.NullInt64
	switch {
	case it.oversize:
		status = "oversize"
	case it.text != "":
		m := hmac.New(sha256.New, s.dedup)
		m.Write([]byte(it.text))
		h := hex.EncodeToString(m.Sum(nil))
		red, hits, excl := redact(it.text)
		hj, _ := json.Marshal(hits)
		var nonce, ct []byte
		status = "stored"
		if excl != "" {
			status = "excluded"
		} else {
			nonce, ct = s.seal("content|"+h, red)
		}
		// Text keeps its first capture's expiry; repeats only add occurrences. Text that already
		// expired but awaits the hourly cleanup is removed here, so a repeat starts a new content
		// row (new id, no old reviews) instead of attaching to unreadable text.
		if _, err := tx.Exec(`UPDATE occurrences SET content_status = 'expired'
			WHERE content_id IN (SELECT id FROM contents WHERE hmac = ? AND expires_at <= ?)`, h, now.Unix()); err != nil {
			return "", err
		}
		if _, err := tx.Exec(`DELETE FROM contents WHERE hmac = ? AND expires_at <= ?`, h, now.Unix()); err != nil {
			return "", err
		}
		err = tx.QueryRow(`INSERT INTO contents (hmac, status, exclude_reason, key_id, nonce, ciphertext, text_bytes,
			redactions, redaction_version, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(hmac) DO UPDATE SET hmac = hmac RETURNING id, status`,
			h, status, excl, s.keyID, nonce, ct, len(it.text), string(hj), redactionVersion, now.Unix(), exp).
			Scan(&contentID, &status)
		if err != nil {
			return "", err
		}
	}
	e := it.ev
	cats, _ := json.Marshal(e.Categories)
	if e.Categories == nil {
		cats = []byte("[]")
	}
	_, err = tx.Exec(`INSERT INTO occurrences (trace_id, content_id, content_status, ts, phase, protocol, path_template,
		coverage, coverage_reason, inspected_chars, truncated, base, enriched, sampling, decision, reason_code, label,
		categories, classifier, classifier_status, classifier_ms, cache_hit, policy_version, enforced, would_block,
		http_status, client_aborted, latency_ms, expires_at, credential_hmac, client, model)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(trace_id) DO NOTHING`,
		e.TraceID, contentID, status, e.Timestamp.Unix(), e.Phase, e.Protocol, e.PathTemplate,
		e.Coverage, e.CoverageReason, e.InspectedChars, it.truncated, it.base, it.enriched, s.cfg.sampling(),
		e.Decision, e.ReasonCode, e.Label, string(cats), e.Classifier, e.ClassifierStatus, e.ClassifierMS, e.CacheHit,
		e.PolicyVersion, e.Enforced, e.WouldBlock, e.HTTPStatus, e.ClientAborted, e.LatencyMS, exp,
		e.CredentialHMAC, e.Client, e.Model)
	if err != nil {
		return "", err
	}
	return "", tx.Commit()
}

// Occurrence is one sampled request: metadata only, safe for any console session.
type Occurrence struct {
	ID               int64    `json:"id"`
	TraceID          string   `json:"trace_id"`
	ContentID        int64    `json:"content_id,omitempty"`
	ContentStatus    string   `json:"content_status"`
	Timestamp        int64    `json:"ts"`
	Phase            string   `json:"phase"`
	Protocol         string   `json:"protocol"`
	PathTemplate     string   `json:"path_template"`
	Coverage         string   `json:"coverage"`
	CoverageReason   string   `json:"coverage_reason,omitempty"`
	InspectedChars   int      `json:"inspected_chars"`
	Truncated        bool     `json:"truncated"`
	Base             bool     `json:"base"`
	Enriched         bool     `json:"enriched"`
	Sampling         string   `json:"sampling"`
	Decision         string   `json:"decision"`
	ReasonCode       string   `json:"reason_code,omitempty"`
	Label            string   `json:"label,omitempty"`
	Categories       []string `json:"categories"`
	Classifier       string   `json:"classifier,omitempty"`
	ClassifierStatus string   `json:"classifier_status,omitempty"`
	ClassifierMS     int64    `json:"classifier_ms"`
	CacheHit         bool     `json:"cache_hit"`
	PolicyVersion    string   `json:"policy_version"`
	Enforced         bool     `json:"enforced"`
	WouldBlock       bool     `json:"would_block"`
	HTTPStatus       int      `json:"http_status"`
	ClientAborted    bool     `json:"client_aborted"`
	LatencyMS        int64    `json:"latency_ms"`
	ExpiresAt        int64    `json:"expires_at"`
	Seen             int      `json:"seen"`       // requests sharing this text
	CacheHits        int      `json:"cache_hits"` // of those, answered from the classifier cache
	ReviewStatus     string   `json:"review_status"`
	ExpectedAction   string   `json:"expected_action,omitempty"`
	CredentialHMAC   string   `json:"credential_hmac,omitempty"`
	Client           string   `json:"client,omitempty"`
	Model            string   `json:"model,omitempty"`
}

const occCols = `o.id, o.trace_id, coalesce(o.content_id, 0), o.content_status, o.ts, o.phase, o.protocol, o.path_template,
	o.coverage, o.coverage_reason, o.inspected_chars, o.truncated, o.base, o.enriched, o.sampling, o.decision, o.reason_code,
	o.label, o.categories, o.classifier, o.classifier_status, o.classifier_ms, o.cache_hit, o.policy_version, o.enforced,
	o.would_block, o.http_status, o.client_aborted, o.latency_ms, o.expires_at,
	(SELECT count(*) FROM occurrences o2 WHERE o2.content_id = o.content_id),
	(SELECT count(*) FROM occurrences o2 WHERE o2.content_id = o.content_id AND o2.cache_hit = 1),
	coalesce((SELECT r.status FROM reviews r WHERE r.content_id = o.content_id ORDER BY r.id DESC LIMIT 1), 'pending'),
	coalesce((SELECT r.expected_action FROM reviews r WHERE r.content_id = o.content_id ORDER BY r.id DESC LIMIT 1), ''),
	o.credential_hmac, o.client, o.model`

func scanOcc(sc interface{ Scan(...any) error }) (Occurrence, error) {
	var o Occurrence
	var cats string
	err := sc.Scan(&o.ID, &o.TraceID, &o.ContentID, &o.ContentStatus, &o.Timestamp, &o.Phase, &o.Protocol, &o.PathTemplate,
		&o.Coverage, &o.CoverageReason, &o.InspectedChars, &o.Truncated, &o.Base, &o.Enriched, &o.Sampling, &o.Decision,
		&o.ReasonCode, &o.Label, &cats, &o.Classifier, &o.ClassifierStatus, &o.ClassifierMS, &o.CacheHit, &o.PolicyVersion,
		&o.Enforced, &o.WouldBlock, &o.HTTPStatus, &o.ClientAborted, &o.LatencyMS, &o.ExpiresAt, &o.Seen,
		&o.CacheHits, &o.ReviewStatus, &o.ExpectedAction, &o.CredentialHMAC, &o.Client, &o.Model)
	json.Unmarshal([]byte(cats), &o.Categories)
	if o.ContentID == 0 {
		o.Seen, o.CacheHits, o.ReviewStatus = 1, 0, "pending"
		if o.CacheHit {
			o.CacheHits = 1
		}
	}
	return o, err
}

type Filter struct {
	Queue      string // base | enriched
	Decision   string
	Review     string // pending | reviewed
	Content    int64  // only occurrences of this content
	Credential string // only requests with this key fingerprint
	Group      bool   // one row per content: its newest matching occurrence
	Before     int64  // id cursor for paging (newest first)
	Limit      int
}

func (s *Store) List(f Filter) ([]Occurrence, error) {
	q := ` FROM occurrences o WHERE o.expires_at > ?`
	args := []any{s.now().Unix()}
	if f.Content > 0 {
		q += ` AND o.content_id = ?`
		args = append(args, f.Content)
	}
	if f.Credential != "" {
		q += ` AND o.credential_hmac = ?`
		args = append(args, f.Credential)
	}
	switch f.Queue {
	case "base":
		q += ` AND o.base = 1`
	case "enriched":
		q += ` AND o.base = 0 AND o.enriched = 1`
	}
	if f.Decision != "" {
		q += ` AND o.decision = ?`
		args = append(args, f.Decision)
	}
	reviewed := `EXISTS (SELECT 1 FROM reviews r WHERE r.content_id = o.content_id)`
	switch f.Review {
	case "pending":
		q += ` AND NOT ` + reviewed
	case "reviewed":
		q += ` AND ` + reviewed
	}
	if f.Group {
		// Metadata-only rows (no content) stay one row each.
		q = ` FROM occurrences o WHERE o.id IN (SELECT max(o.id)` + q + ` GROUP BY coalesce(o.content_id, -o.id))`
	}
	q = `SELECT ` + occCols + q
	if f.Before > 0 {
		q += ` AND o.id < ?`
		args = append(args, f.Before)
	}
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 50
	}
	q += ` ORDER BY o.id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Occurrence{}
	for rows.Next() {
		o, err := scanOcc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

type Review struct {
	ID             int64  `json:"id"`
	Actor          string `json:"actor"`
	CreatedAt      int64  `json:"created_at"`
	PolicyVersion  string `json:"policy_version"`
	Status         string `json:"status"`
	ExpectedAction string `json:"expected_action,omitempty"`
	Category       string `json:"category,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Supersedes     int64  `json:"supersedes,omitempty"`
}

// Detail is a sample with its decrypted (redacted) text and review history: reviewer only.
type Detail struct {
	Occurrence
	Text          string         `json:"text,omitempty"`
	TextBytes     int            `json:"text_bytes,omitempty"`
	ExcludeReason string         `json:"exclude_reason,omitempty"`
	Redactions    map[string]int `json:"redactions,omitempty"`
	Reviews       []Review       `json:"reviews"`
}

func (s *Store) Get(id int64) (*Detail, error) {
	now := s.now().Unix()
	o, err := scanOcc(s.db.QueryRow(`SELECT `+occCols+` FROM occurrences o WHERE o.id = ? AND o.expires_at > ?`, id, now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := &Detail{Occurrence: o, Reviews: []Review{}}
	if o.ContentID == 0 {
		return d, nil
	}
	var h, red string
	var excl sql.NullString
	var nonce, ct []byte
	var exp int64
	err = s.db.QueryRow(`SELECT hmac, exclude_reason, nonce, ciphertext, text_bytes, redactions, expires_at FROM contents WHERE id = ?`,
		o.ContentID).Scan(&h, &excl, &nonce, &ct, &d.TextBytes, &red, &exp)
	if errors.Is(err, sql.ErrNoRows) || err == nil && exp <= now {
		d.ContentStatus = "expired" // checked on read, not only by the hourly cleanup
	} else if err != nil {
		return nil, err
	} else {
		d.ExcludeReason = excl.String
		json.Unmarshal([]byte(red), &d.Redactions)
		if ct != nil {
			if d.Text, err = s.open("content|"+h, nonce, ct); err != nil {
				return nil, fmt.Errorf("decrypt sample %d: %w", id, err)
			}
		}
	}
	rows, err := s.db.Query(`SELECT id, actor, created_at, policy_version, status, expected_action, category, reason_nonce,
		reason_ct, coalesce(supersedes, 0) FROM reviews WHERE content_id = ? ORDER BY id DESC`, o.ContentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Review
		var rn, rc []byte
		var created int64 // unix nanos; also binds the reason ciphertext to this revision
		if err := rows.Scan(&r.ID, &r.Actor, &created, &r.PolicyVersion, &r.Status, &r.ExpectedAction, &r.Category,
			&rn, &rc, &r.Supersedes); err != nil {
			return nil, err
		}
		r.CreatedAt = created / int64(time.Second)
		if rc != nil {
			if r.Reason, err = s.open(fmt.Sprintf("review|%d|%d", o.ContentID, created), rn, rc); err != nil {
				return nil, fmt.Errorf("decrypt review %d: %w", r.ID, err)
			}
		}
		d.Reviews = append(d.Reviews, r)
	}
	return d, rows.Err()
}

var reviewStatuses = []string{"labeled", "insufficient_context", "disputed", "excluded_sensitive"}

type ReviewInput struct {
	Status         string `json:"status"`
	ExpectedAction string `json:"expected_action"`
	Category       string `json:"category"`
	Reason         string `json:"reason"`
	// Supersedes is the latest review the reviewer saw (0 for none); a newer one means 409.
	Supersedes int64 `json:"supersedes"`
}

// AddReview appends a review revision for the text behind occurrence id. Reviews are never edited.
func (s *Store) AddReview(id int64, actor, policyVersion string, in ReviewInput) (int64, error) {
	if !oneOf(in.Status, reviewStatuses...) || len(in.Reason) > 2000 ||
		(in.Status == "labeled") != oneOf(in.ExpectedAction, "allow", "review", "deny") ||
		in.Category != "" && !oneOf(in.Category, classifier.KnownCategories...) {
		return 0, ErrInvalid
	}
	if s.full() != "" {
		return 0, ErrFull
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var contentID int64
	err = tx.QueryRow(`SELECT coalesce(content_id, 0) FROM occurrences WHERE id = ? AND expires_at > ?`, id, s.now().Unix()).Scan(&contentID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && contentID == 0 {
		return 0, ErrNotFound // nothing to review without text
	}
	if err != nil {
		return 0, err
	}
	var latest int64
	if err := tx.QueryRow(`SELECT coalesce(max(id), 0) FROM reviews WHERE content_id = ?`, contentID).Scan(&latest); err != nil {
		return 0, err
	}
	if latest != in.Supersedes {
		return 0, ErrConflict
	}
	now := s.now()
	var rn, rc []byte
	if in.Reason = strings.TrimSpace(in.Reason); in.Reason != "" {
		rn, rc = s.seal(fmt.Sprintf("review|%d|%d", contentID, now.UnixNano()), in.Reason)
	}
	var sup sql.NullInt64
	if latest > 0 {
		sup = sql.NullInt64{Int64: latest, Valid: true}
	}
	res, err := tx.Exec(`INSERT INTO reviews (content_id, actor, created_at, policy_version, status, expected_action, category,
		reason_nonce, reason_ct, supersedes, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		contentID, actor, now.UnixNano(), policyVersion, in.Status, in.ExpectedAction, in.Category, rn, rc, sup,
		now.Add(s.cfg.ReviewRetention).Unix())
	if err != nil {
		return 0, err
	}
	rid, _ := res.LastInsertId()
	return rid, tx.Commit()
}

// Delete removes the text and every review of the sample's content; occurrence metadata stays
// (marked deleted) until it expires.
func (s *Store) Delete(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var contentID int64
	err = tx.QueryRow(`SELECT coalesce(content_id, 0) FROM occurrences WHERE id = ?`, id).Scan(&contentID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if contentID != 0 {
		for _, q := range []string{
			`UPDATE occurrences SET content_status = 'deleted' WHERE content_id = ?`,
			`DELETE FROM reviews WHERE content_id = ?`,
			`DELETE FROM contents WHERE id = ?`,
		} {
			if _, err := tx.Exec(q, contentID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Audit records who did what to which sample; it never carries text or reasons.
func (s *Store) Audit(actor, action, object, result string) error {
	if s.full() != "" {
		return ErrFull // callers that show text fail closed on this
	}
	_, err := s.db.Exec(`INSERT INTO access_audit (ts, actor, action, object, result) VALUES (?,?,?,?,?)`,
		s.now().Unix(), actor, action, object, result)
	return err
}

// cleanup drops expired rows. Expired text is already unreadable through Get.
func (s *Store) cleanup() error {
	now := s.now()
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{`UPDATE occurrences SET content_status = 'expired' WHERE content_id IN (SELECT id FROM contents WHERE expires_at <= ?)`, now.Unix()},
		{`DELETE FROM contents WHERE expires_at <= ?`, now.Unix()},
		{`DELETE FROM occurrences WHERE expires_at <= ?`, now.Unix()},
		{`DELETE FROM reviews WHERE expires_at <= ?`, now.Unix()},
		{`DELETE FROM access_audit WHERE ts <= ?`, now.Add(-s.cfg.AuditRetention).Unix()},
	} {
		if _, err := s.db.Exec(q.sql, q.arg); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`DELETE FROM counters WHERE day < ?`, now.Add(-s.cfg.AuditRetention).UTC().Format(time.DateOnly))
	return err
}

func (s *Store) loadCounters(day string) (map[string]int, error) {
	rows, err := s.db.Query(`SELECT key, n FROM counters WHERE day = ?`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		m[k] = n
	}
	return m, rows.Err()
}

func (s *Store) saveCounters(day string, m map[string]int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, n := range m {
		if _, err := tx.Exec(`INSERT INTO counters (day, key, n) VALUES (?,?,?) ON CONFLICT(day, key) DO UPDATE SET n = excluded.n`,
			day, k, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}
