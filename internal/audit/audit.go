// Package audit writes one metadata-only JSON line per request. It never receives bodies, headers,
// query strings or raw client addresses, so it cannot leak them.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Event struct {
	Timestamp    time.Time `json:"timestamp"`
	TraceID      string    `json:"trace_id"`
	Phase        string    `json:"phase"`
	RouteClass   string    `json:"route_class"`
	Protocol     string    `json:"protocol,omitempty"`
	Method       string    `json:"method"`
	PathTemplate string    `json:"path_template"`
	SourceIPHMAC string    `json:"source_ip_hmac,omitempty"`
	// CredentialHMAC fingerprints the client's API key (same keyed HMAC as the IP, own prefix):
	// it groups one key's requests, it is not an identity and New API alone validates the key.
	CredentialHMAC string `json:"credential_hmac,omitempty"`
	Client         string `json:"client,omitempty"` // User-Agent product token, e.g. "codex-tui/0.164.0"
	Model          string `json:"model,omitempty"`  // requested model name, sanitised
	BodyBytes      int64  `json:"body_bytes"`
	Decision       string `json:"decision"`
	ReasonCode     string `json:"reason_code,omitempty"`
	Coverage       string `json:"coverage,omitempty"`
	// CoverageReason explains partial coverage (TRUNCATED, HISTORY_NOT_INSPECTED, ...).
	// It is the first matching reason only; e.g. a truncated turn with history says TRUNCATED.
	CoverageReason string `json:"coverage_reason,omitempty"`
	// UserText is the state of the latest user text after extraction: complete | truncated |
	// absent. Empty when extraction did not run or could not parse the body.
	UserText         string `json:"user_text,omitempty"`
	InspectedChars   int    `json:"inspected_chars,omitempty"`
	Classifier       string `json:"classifier,omitempty"`
	ClassifierStatus string `json:"classifier_status,omitempty"`
	ClassifierMS     int64  `json:"classifier_ms,omitempty"`
	// ClassifierRetried: the first call failed (hang, connection, 5xx) and was retried once.
	ClassifierRetried bool     `json:"classifier_retried,omitempty"`
	Label             string   `json:"label,omitempty"`
	Categories        []string `json:"categories,omitempty"`
	CacheHit          bool     `json:"cache_hit,omitempty"`
	// Aux* record the optional shadow-only System One judge: P(yes) per question, never text.
	AuxModel      string             `json:"aux_model,omitempty"`
	AuxStatus     string             `json:"aux_status,omitempty"`
	AuxMS         int64              `json:"aux_ms,omitempty"`
	Aux           map[string]float64 `json:"aux,omitempty"`
	PolicyVersion string             `json:"policy_version,omitempty"`
	WouldBlock    bool               `json:"would_block,omitempty"`
	Enforced      bool               `json:"enforced,omitempty"`
	HTTPStatus    int                `json:"http_status"`
	LatencyMS     int64              `json:"latency_ms"`
	ClientAborted bool               `json:"client_aborted,omitempty"`
}

// Logger serialises events to w. A failing writer never fails the request: the error is counted
// and reported on stderr at most once per minute.
type Logger struct {
	mu        sync.Mutex
	w         io.Writer
	key       []byte
	failures  int
	lastAlarm time.Time
	// OnLog, when set before serving, receives every event after it is written (console stats).
	OnLog func(Event)
}

func New(w io.Writer, hmacKey []byte) *Logger {
	return &Logger{w: w, key: hmacKey}
}

// Fingerprint is a truncated, rotatable HMAC; it is an analysis label, not an identity.
func (l *Logger) Fingerprint(v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, l.key)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

func (l *Logger) Log(e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(b); err != nil {
		l.failures++
		if time.Since(l.lastAlarm) >= time.Minute {
			fmt.Fprintf(os.Stderr, "riskguard: audit write failed (%d failures so far): %v\n", l.failures, err)
			l.lastAlarm = time.Now()
		}
	}
	if l.OnLog != nil {
		l.OnLog(e)
	}
}

func (l *Logger) Failures() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures
}
