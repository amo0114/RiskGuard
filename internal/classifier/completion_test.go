package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestModerateRequiresCompletedGeneration(t *testing.T) {
	for _, reason := range []any{"stop", "length", "content_filter", "tool_calls", "cancelled", "", nil, 42} {
		t.Run(fmt.Sprint(reason), func(t *testing.T) {
			q := llama(t, func(w http.ResponseWriter, r *http.Request) {
				choice := map[string]any{"message": map[string]string{"content": "Safety: Safe\nCategories: None"}}
				if reason != nil { // nil tests a missing finish_reason
					choice["finish_reason"] = reason
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{choice}})
			})
			res := q.Moderate(context.Background(), "synthetic prompt")
			if reason == "stop" {
				if res.Status != "ok" || res.Label != Safe {
					t.Fatalf("completed result: %+v", res)
				}
			} else if res.Status != "parse_failed" || res.Label != Unknown {
				t.Fatalf("incomplete result accepted: %+v", res)
			}
		})
	}
}

func TestModerateNeverFollowsRedirect(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var reached, calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				reply(w, "Safety: Safe")
			}))
			defer target.Close()
			q := llama(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				http.Redirect(w, r, target.URL+"/collect", code)
			})
			res := q.Moderate(context.Background(), "synthetic private prompt")
			if reached.Load() != 0 || calls.Load() != 1 || res.Status != fmt.Sprintf("http_%d", code) || res.Label != Unknown {
				t.Fatalf("redirect handling: result=%+v origin=%d target=%d", res, calls.Load(), reached.Load())
			}
		})
	}
}
