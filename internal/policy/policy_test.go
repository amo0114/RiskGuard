package policy

import (
	"os"
	"path/filepath"
	"testing"

	"riskguard/internal/classifier"
)

func load(t *testing.T) *Policy {
	t.Helper()
	p, err := Load("../../config/policy-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDraftPolicyNeverAutoDenies(t *testing.T) {
	p := load(t)
	for _, c := range classifier.KnownCategories {
		d := p.Classified(classifier.Result{Status: "ok", Label: classifier.Unsafe, Categories: []string{c}})
		if d.Decision == Deny {
			t.Errorf("draft policy denies %s", c)
		}
	}
}

func TestClassifiedMapping(t *testing.T) {
	p := load(t)
	p.UnsafeCategories["Violent"] = Deny // as if approved after evaluation
	cases := []struct {
		r    classifier.Result
		want Decision
	}{
		{classifier.Result{Status: "ok", Label: classifier.Safe}, Decision{Allow, "CLASSIFIER_SAFE"}},
		{classifier.Result{Status: "ok", Label: classifier.Controversial}, Decision{Review, "AMBIGUOUS"}},
		{classifier.Result{Status: "ok", Label: classifier.Unsafe, Categories: []string{"Violent"}}, Decision{Deny, "POLICY_HIGH_RISK"}},
		{classifier.Result{Status: "ok", Label: classifier.Unsafe, Categories: []string{"Copyright Violation", "Violent"}}, Decision{Deny, "POLICY_HIGH_RISK"}},
		{classifier.Result{Status: "ok", Label: classifier.Unsafe, Categories: []string{"Copyright Violation"}}, Decision{Allow, "POLICY_ALLOWED_CATEGORY"}},
		{classifier.Result{Status: "ok", Label: classifier.Unsafe, Categories: []string{"Jailbreak"}}, Decision{Review, "POLICY_REVIEW"}},
		{classifier.Result{Status: "ok", Label: classifier.Unsafe}, Decision{Review, "POLICY_UNSAFE_UNCATEGORISED"}},
		{classifier.Result{Status: "parse_failed", Label: classifier.Unknown}, Decision{Review, "PARSE_FAILED"}},
		{classifier.Result{Status: "timeout", Label: classifier.Unknown}, Decision{Unavailable, "MODEL_TIMEOUT"}},
		{classifier.Result{Status: "too_long", Label: classifier.Unknown}, Decision{Review, "INPUT_TOO_LONG"}},
		{classifier.Result{Status: "http_500", Label: classifier.Unknown}, Decision{Unavailable, "MODEL_UNAVAILABLE"}},
	}
	for _, c := range cases {
		if got := p.Classified(c.r); got != c.want {
			t.Errorf("%+v -> %+v want %+v", c.r, got, c.want)
		}
	}
}

func TestActions(t *testing.T) {
	p := load(t)
	cases := []struct {
		d       Decision
		forward bool
		status  int
	}{
		{Decision{Allow, ""}, true, 0},
		{Decision{Deny, "POLICY_HIGH_RISK"}, false, 403},
		{Decision{Review, "AMBIGUOUS"}, false, 422},
		{Decision{Unavailable, "MODEL_TIMEOUT"}, false, 503},
		{Decision{Unsupported, "NO_INSPECTABLE_INPUT"}, true, 0},
		{Decision{Unsupported, "PARSE_FAILED"}, false, 400},
		{Decision{Unsupported, "COVERAGE_GAP"}, false, 403},
	}
	for _, c := range cases {
		a := p.Action(c.d)
		if a.Forward != c.forward || a.Status != c.status {
			t.Errorf("%+v -> %+v", c.d, a)
		}
	}
	p.Enforce.Review = "forward"
	if !p.Action(Decision{Review, "AMBIGUOUS"}).Forward {
		t.Error("review=forward not honoured")
	}
	if !p.T0Only("embeddings") || p.T0Only("openai_chat") || p.Excepted("openai_responses_ws", "/v1/responses") {
		t.Error("exception lists")
	}
}

func TestValidation(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]string{
		"unknown category":                    "version: v\nlabels: {Safe: allow, Controversial: review, Unknown: review}\nunsafe_categories: {Hacking: deny}\nunsafe_default: review\nenforce: {review: reject, no_inspectable_input: forward, unparseable: reject}\n",
		"unknown as allow ok but bad default": "version: v\nlabels: {Safe: allow, Controversial: review, Unknown: review}\nunsafe_default: allow\nenforce: {review: reject, no_inspectable_input: forward, unparseable: reject}\n",
		"missing labels":                      "version: v\nunsafe_default: review\nenforce: {review: reject, no_inspectable_input: forward, unparseable: reject}\n",
		"typo field":                          "version: v\nlabel: {}\n",
		"bad enforce":                         "version: v\nlabels: {Safe: allow, Controversial: review, Unknown: review}\nunsafe_default: review\nenforce: {review: maybe, no_inspectable_input: forward, unparseable: reject}\n",
	}
	for name, body := range bad {
		f := filepath.Join(dir, "p.yaml")
		os.WriteFile(f, []byte(body), 0o600)
		if _, err := Load(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
