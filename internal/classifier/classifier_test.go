package classifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in    string
		label string
		cats  []string
		ok    bool
	}{
		{"Safety: Safe\nCategories: None", Safe, nil, true},
		{"Safety: Safe", Safe, nil, true},
		{"Safety: Unsafe\nCategories: Violent", Unsafe, []string{"Violent"}, true},
		{"Safety: Unsafe\nCategories: Non-violent Illegal Acts, Jailbreak\n", Unsafe, []string{"Non-violent Illegal Acts", "Jailbreak"}, true},
		{"Safety: Controversial\nCategories: Politically Sensitive Topics", Controversial, []string{"Politically Sensitive Topics"}, true},
		{"<think>\n</think>\n\nSafety: Unsafe\nCategories: PII", Unsafe, []string{"PII"}, true},
		{"", Unknown, nil, false},
		{"safe", Unknown, nil, false},
		{"Safety: Probably fine", Unknown, nil, false},
		{"Safety: Safe\nSafety: Unsafe", Unknown, nil, false},        // ambiguous
		{"Safety: Unsafe\nCategories: Hacking", Unknown, nil, false}, // drifted category
		{"Safety: Safe\nCategories: None\nCategories: Violent", Unknown, nil, false},
		{`{"confidence":0.99,"label":"Safe"}`, Unknown, nil, false},
	}
	for _, c := range cases {
		label, cats, ok := Parse(c.in)
		if label != c.label || ok != c.ok || strings.Join(cats, "|") != strings.Join(c.cats, "|") {
			t.Errorf("%q -> %s %v %v", c.in, label, cats, ok)
		}
	}
}

func llama(t *testing.T, h http.HandlerFunc) *Qwen {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewQwen(srv.URL, "Qwen3Guard-Gen-0.6B", "test-key", 128)
}

func reply(w http.ResponseWriter, content string) {
	json.NewEncoder(w).Encode(map[string]any{
		"model":   "Qwen3Guard-Gen-0.6B",
		"choices": []map[string]any{{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": content}}},
	})
}

func TestModerateRequestShapeAndResult(t *testing.T) {
	var got map[string]any
	var auth string
	q := llama(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		reply(w, "Safety: Unsafe\nCategories: Violent")
	})
	res := q.Moderate(context.Background(), "some text")
	if res.Status != "ok" || res.Label != Unsafe || len(res.Categories) != 1 || res.ModelID != "Qwen3Guard-Gen-0.6B" || res.Duration <= 0 {
		t.Fatalf("%+v", res)
	}
	if auth != "Bearer test-key" || got["max_tokens"].(float64) != 128 || got["temperature"].(float64) != 0 || got["stream"] != false {
		t.Errorf("request: %v %v", auth, got)
	}
	msgs := got["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["content"] != "some text" {
		t.Errorf("messages: %v", msgs)
	}
}

func TestModerateFailureModesNeverSafe(t *testing.T) {
	var calls atomic.Int32
	cases := map[string]http.HandlerFunc{
		"http_500":     func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) },
		"http_401":     func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(401) },
		"parse_failed": func(w http.ResponseWriter, r *http.Request) { calls.Add(1); reply(w, "I think this is fine") },
		"empty":        func(w http.ResponseWriter, r *http.Request) { calls.Add(1); reply(w, "") },
		"not json":     func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "<html>") },
		"huge":         func(w http.ResponseWriter, r *http.Request) { calls.Add(1); reply(w, strings.Repeat("x", 100<<10)) },
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			reply(w, "Safety: Safe")
		},
	}
	for name, h := range cases {
		calls.Store(0)
		q := llama(t, h)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		res := q.Moderate(ctx, "x")
		cancel()
		if res.Label != Unknown || res.Status == "ok" || calls.Load() != 1 {
			t.Errorf("%s: %+v calls=%d", name, res, calls.Load())
		}
		if name == "timeout" && res.Status != "timeout" {
			t.Errorf("timeout status %q", res.Status)
		}
	}
	q := llama(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":{"code":400,"message":"request (2990 tokens) exceeds the available context size (2048 tokens)","type":"exceed_context_size_error"}}`)
	})
	if res := q.Moderate(context.Background(), "x"); res.Status != "too_long" || res.Label != Unknown {
		t.Errorf("context overflow: %+v", res)
	}
	q = NewQwen("http://127.0.0.1:1", "m", "k", 128)
	if res := q.Moderate(context.Background(), "x"); res.Status != "unavailable" || res.Label != Unknown {
		t.Errorf("connection refused: %+v", res)
	}
}
