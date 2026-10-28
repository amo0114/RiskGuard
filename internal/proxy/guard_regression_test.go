package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"riskguard/internal/classifier"
	"riskguard/internal/limits"
)

func assertForwardedBytes(t *testing.T, h *harness, body string) {
	t.Helper()
	want := sha256.Sum256([]byte(body))
	h.up.mu.Lock()
	defer h.up.mu.Unlock()
	if h.up.last.bodySHA != hex.EncodeToString(want[:]) || h.up.last.bodyLen != len(body) {
		t.Fatal("forwarded request bytes changed")
	}
}

func TestDuplicateInputCannotBypassEnforcement(t *testing.T) {
	body := `{"input":"benign","input":[{"role":"user","content":[{"type":"input_text","text":"BLOCKME"}]}]}`
	for _, mode := range []string{"enforce", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			c := keywordClassifier()
			g := testGuard(t, c)
			h := newHarnessMode(t, mode, 1<<20, g)
			resp, _ := post(t, h.guard.URL+"/v1/responses", body)
			waitLines(t, h, 1)
			ev := lastEvent(t, h)
			if ev.ReasonCode != "DUPLICATE_KEY" || c.calls.Load() != 0 {
				t.Fatalf("ambiguous input classified: %+v", ev)
			}
			if mode == "enforce" {
				if resp.StatusCode != 400 || h.up.hits.Load() != 0 {
					t.Fatalf("bypass: status=%d hits=%d", resp.StatusCode, h.up.hits.Load())
				}
			} else {
				if resp.StatusCode != 418 || !ev.WouldBlock {
					t.Fatalf("shadow: %+v", ev)
				}
				assertForwardedBytes(t, h, body)
			}
			assertSpoolReleased(t, g.Spool)
		})
	}
}

func TestSpoolStorageFailureReturns503AndRecovers(t *testing.T) {
	for _, mode := range []string{"enforce", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			c := safeClassifier()
			g := testGuard(t, c)
			g.Spool.memLimit = 1
			if err := os.Remove(g.Spool.dir); err != nil {
				t.Fatal(err)
			}
			h := newHarnessMode(t, mode, 1<<20, g)
			resp, body := post(t, h.guard.URL+"/v1/chat/completions", chatBody("normal coding request"))
			waitLines(t, h, 1)
			ev := lastEvent(t, h)
			if resp.StatusCode != 503 || !strings.Contains(body, "GUARD_UNAVAILABLE") || ev.HTTPStatus != 503 || ev.ReasonCode != "SPOOL_IO_FAILED" || h.up.hits.Load() != 0 || c.calls.Load() != 0 {
				t.Fatalf("storage failure: status=%d body=%s audit=%+v", resp.StatusCode, body, ev)
			}
			assertSpoolReleased(t, g.Spool)
			if err := os.MkdirAll(g.Spool.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			resp, _ = post(t, h.guard.URL+"/v1/chat/completions", chatBody("normal coding request"))
			waitLines(t, h, 2)
			if resp.StatusCode != 418 || h.up.hits.Load() != 1 {
				t.Fatalf("storage did not recover: %d", resp.StatusCode)
			}
			assertSpoolReleased(t, g.Spool)
		})
	}
}

func TestSpoolRAMFullShadowReplaysEnforceRejects(t *testing.T) {
	body := chatBody(strings.Repeat("normal code ", 700))
	for _, mode := range []string{"shadow", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			g := testGuard(t, safeClassifier())
			var err error
			g.Spool, err = NewSpoolPool(t.TempDir(), 8192, 1<<20, 1, WithSpoolMemoryLimit(4096))
			if err != nil {
				t.Fatal(err)
			}
			h := newHarnessMode(t, mode, 1<<20, g)
			resp, _ := post(t, h.guard.URL+"/v1/chat/completions", body)
			waitLines(t, h, 1)
			ev := lastEvent(t, h)
			if ev.ReasonCode != "SPOOL_FULL" {
				t.Fatalf("audit: %+v", ev)
			}
			if mode == "shadow" {
				if resp.StatusCode != 418 || !ev.WouldBlock {
					t.Fatalf("shadow: status=%d audit=%+v", resp.StatusCode, ev)
				}
				assertForwardedBytes(t, h, body)
			} else if resp.StatusCode != 503 || h.up.hits.Load() != 0 {
				t.Fatalf("enforce: %d", resp.StatusCode)
			}
			assertSpoolReleased(t, g.Spool)
		})
	}
}

func TestShadowSkipsSaturatedExtractionWithoutQueueWait(t *testing.T) {
	c := safeClassifier()
	g := testGuard(t, c)
	g.ExtractGate = limits.NewGate(1, 1)
	g.QueueWait = 30 * time.Second
	release, err := g.ExtractGate.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release() // keep saturated until after the response assertions
	h := newHarnessMode(t, "shadow", 1<<20, g)
	body := chatBody("normal coding request")
	req, _ := http.NewRequest("POST", h.guard.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("shadow waited for extraction queue: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	waitLines(t, h, 1)
	ev := lastEvent(t, h)
	if resp.StatusCode != 418 || ev.ReasonCode != "EXTRACT_BUSY" || c.calls.Load() != 0 {
		t.Fatalf("shadow: %+v", ev)
	}
	assertForwardedBytes(t, h, body)
	assertSpoolReleased(t, g.Spool)
}

func TestTruncatedClassifierResponseNeverCached(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"choices":[{"finish_reason":"length","message":{"content":"Safety: Safe"}}]}`)
	}))
	defer srv.Close()
	g := testGuard(t, classifier.NewQwen(srv.URL, "mock-guard", "local-test-key", 128))
	for i := 0; i < 2; i++ {
		res, hit := g.classify(context.Background(), "synthetic input", 0)
		if hit || res.Status != "parse_failed" || res.Label != classifier.Unknown {
			t.Fatalf("incomplete cached: hit=%v result=%+v", hit, res)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("expected two uncached calls, got %d", calls.Load())
	}
}

func TestOnlineBodyReadFailureReturns400(t *testing.T) {
	g := testGuard(t, safeClassifier())
	h := newHarnessMode(t, "enforce", 1<<20, g)
	u, _ := url.Parse(h.guard.URL)
	// Call the handler with a reader failure and a live context; use no real broken connection.
	req := httptest.NewRequest("POST", u.String()+"/v1/chat/completions", nil)
	req.Body = io.NopCloser(brokenUpload{})
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.guard.Config.Handler.ServeHTTP(rec, req)
	ev := lastEvent(t, h)
	if rec.Code != 400 || ev.HTTPStatus != 400 || ev.ReasonCode != "BODY_READ_FAILED" || h.up.hits.Load() != 0 {
		t.Fatalf("body failure: %s %+v", fmt.Sprint(rec.Code), ev)
	}
	assertSpoolReleased(t, g.Spool)
}
