package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestJudgeNeverFollowsRedirect(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var reached, calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				answers(w, 0.25, "")
			}))
			defer target.Close()
			j := judge(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				http.Redirect(w, r, target.URL+"/collect", code)
			})
			a := j.Ask(context.Background(), "synthetic private text")
			if reached.Load() != 0 || calls.Load() != 1 || a.Status != fmt.Sprintf("http_%d", code) || a.Probs != nil {
				t.Fatalf("redirect: status=%s origin=%d target=%d", a.Status, calls.Load(), reached.Load())
			}
		})
	}
}

func judge(t *testing.T, h http.HandlerFunc) *Judge {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewJudge(srv.URL, "jevos-v5", "test-key", false)
}

func answers(w http.ResponseWriter, p float64, skip string) {
	ans := map[string]any{}
	for id := range JudgeQuestions {
		if id != skip {
			ans[id] = map[string]any{"type": "noul", "noul": p}
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"model": "jevos-v5", "answers": ans})
}

func TestJudgeRequestShapeAndResult(t *testing.T) {
	var got struct {
		Model     string                       `json:"model"`
		State     map[string]string            `json:"state"`
		Questions map[string]map[string]string `json:"questions"`
	}
	var auth, path string
	j := judge(t, func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		answers(w, 0.25, "")
	})
	a := j.Ask(context.Background(), "some text")
	if a.Status != "ok" || len(a.Probs) != len(JudgeQuestions) || a.Probs["dev"] != 0.25 || a.Duration <= 0 {
		t.Fatalf("%+v", a)
	}
	if auth != "Bearer test-key" || path != "/v1/systemone" || got.Model != "jevos-v5" || got.State["user_message"] != "some text" {
		t.Errorf("request: %s %s %+v", auth, path, got)
	}
	for id := range JudgeQuestions {
		if got.Questions[id]["type"] != "noul" || got.Questions[id]["instructions"] == "" {
			t.Errorf("question %s: %v", id, got.Questions[id])
		}
	}
}

func TestJudgeFailureModes(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"http_500":       func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"not json":       func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "<html>") },
		"missing answer": func(w http.ResponseWriter, r *http.Request) { answers(w, 0.5, "dev") },
		"out of range":   func(w http.ResponseWriter, r *http.Request) { answers(w, 1.5, "") },
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		},
	}
	for name, h := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		a := judge(t, h).Ask(ctx, "x")
		cancel()
		if a.Status == "ok" || a.Probs != nil {
			t.Errorf("%s: %+v", name, a)
		}
		if name == "timeout" && a.Status != "timeout" {
			t.Errorf("timeout status %q", a.Status)
		}
	}
}
