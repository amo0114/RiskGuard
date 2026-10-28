// Package classifier adapts Qwen3Guard-Gen (served by llama.cpp's OpenAI-compatible API) to a
// label + categories result. The model output is evidence for the policy, not a decision, and no
// confidence number is invented: Qwen3Guard-Gen does not provide one.
package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	Safe          = "Safe"
	Unsafe        = "Unsafe"
	Controversial = "Controversial"
	Unknown       = "Unknown"
)

// Official Qwen3Guard-Gen category names (prompt moderation).
var KnownCategories = []string{
	"Violent", "Non-violent Illegal Acts", "Sexual Content or Sexual Acts", "PII",
	"Suicide & Self-Harm", "Unethical Acts", "Politically Sensitive Topics", "Copyright Violation", "Jailbreak",
}

type Result struct {
	Label      string
	Categories []string
	ModelID    string
	Duration   time.Duration
	// Status: ok | parse_failed | timeout | unavailable | error
	Status string
	// Retried: the first attempt failed transiently and this is the second (Guard retry policy).
	Retried bool
}

type Classifier interface {
	Moderate(ctx context.Context, text string) Result
}

type Qwen struct {
	endpoint  string // e.g. http://127.0.0.1:8088
	model     string
	apiKey    string
	maxTokens int
	client    *http.Client
}

func NewQwen(endpoint, model, apiKey string, maxTokens int) *Qwen {
	return &Qwen{
		endpoint: strings.TrimRight(endpoint, "/"), model: model, apiKey: apiKey, maxTokens: maxTokens,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never replay user text to another endpoint
		}, Transport: &http.Transport{
			Proxy:               nil, // private link only; never via an environment proxy
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
		}},
	}
}

const maxResponseBytes = 64 << 10

// Moderate makes exactly one call; the caller's ctx carries the timeout. No retries.
func (q *Qwen) Moderate(ctx context.Context, text string) (res Result) {
	start := time.Now()
	res = Result{Label: Unknown, ModelID: q.model}
	// named result: the deferred assignment must reach the caller on every return path
	defer func() { res.Duration = time.Since(start) }()

	payload, _ := json.Marshal(map[string]any{
		"model":       q.model,
		"messages":    []map[string]string{{"role": "user", "content": text}},
		"max_tokens":  q.maxTokens,
		"temperature": 0,
		"stream":      false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.endpoint+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		res.Status = "error"
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+q.apiKey)
	resp, err := q.client.Do(req)
	if err != nil {
		res.Status = "unavailable"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.Status = "timeout"
		}
		return res
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		res.Status = "unavailable"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.Status = "timeout"
		}
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Status = fmt.Sprintf("http_%d", resp.StatusCode)
		// llama.cpp rejects prompts larger than a slot; that is a property of the input (e.g. a
		// pasted hex dump), not an outage, so it must not surface as GUARD_UNAVAILABLE.
		if resp.StatusCode == http.StatusBadRequest && bytes.Contains(body, []byte("exceed_context_size_error")) {
			res.Status = "too_long"
		}
		return res
	}
	if len(body) > maxResponseBytes {
		res.Status = "parse_failed"
		return res
	}
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Choices) != 1 || out.Choices[0].FinishReason != "stop" {
		res.Status = "parse_failed"
		return res
	}
	if out.Model != "" {
		res.ModelID = out.Model
	}
	label, cats, ok := Parse(out.Choices[0].Message.Content)
	if !ok {
		res.Status = "parse_failed"
		return res
	}
	res.Label, res.Categories, res.Status = label, cats, "ok"
	return res
}

var (
	thinkRe    = regexp.MustCompile(`(?s)<think>.*?</think>`)
	safetyRe   = regexp.MustCompile(`(?m)^\s*Safety:\s*(Safe|Unsafe|Controversial)\s*$`)
	categoryRe = regexp.MustCompile(`(?m)^\s*Categories:\s*(.*?)\s*$`)
)

// Parse reads the Qwen3Guard-Gen output format:
//
//	Safety: Unsafe
//	Categories: Violent, Jailbreak
//
// It requires exactly one Safety line, accepts only official category names, and maps
// "None" to no categories. Anything else is a parse failure (Unknown), never Safe.
func Parse(s string) (label string, categories []string, ok bool) {
	s = thinkRe.ReplaceAllString(s, "")
	m := safetyRe.FindAllStringSubmatch(s, -1)
	if len(m) != 1 {
		return Unknown, nil, false
	}
	label = m[0][1]
	cm := categoryRe.FindAllStringSubmatch(s, -1)
	if len(cm) > 1 {
		return Unknown, nil, false
	}
	if len(cm) == 1 {
		for _, c := range strings.Split(cm[0][1], ",") {
			c = strings.TrimSpace(c)
			switch {
			case c == "" || strings.EqualFold(c, "None"):
			case known(c):
				categories = append(categories, c)
			default:
				return Unknown, nil, false
			}
		}
	}
	return label, categories, true
}

func known(c string) bool {
	for _, k := range KnownCategories {
		if k == c {
			return true
		}
	}
	return false
}
