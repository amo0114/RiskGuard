package main

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"riskguard/internal/policy"
)

func TestLoadScenarios(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenarios.jsonl")
	if err := os.WriteFile(path, []byte("{\"id\":\"first\"}\n{\"id\":\"last\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scs, err := load(path)
	if err != nil || len(scs) != 2 || scs[0].ID != "first" || scs[1].ID != "last" {
		t.Fatalf("load: %v %+v", err, scs)
	}
	if scs, err := load(path + ".missing"); err == nil || scs != nil {
		t.Fatalf("missing file accepted: %v %+v", err, scs)
	}
}

func TestScanScenariosRejectsIncompleteInput(t *testing.T) {
	for name, input := range map[string]string{
		"malformed": "{\"id\":\"first\"}\n{broken\n{\"id\":\"last\"}\n",
		"oversized": "{\"id\":\"first\"}\n{\"id\":\"large\",\"body\":\"" + strings.Repeat("x", 17<<20) + "\"}\n{\"id\":\"last\"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			scs, err := scanScenarios("synthetic.jsonl", strings.NewReader(input))
			if err == nil || scs != nil || !strings.Contains(err.Error(), "synthetic.jsonl") || !strings.Contains(err.Error(), "line 2") {
				t.Fatalf("incomplete input accepted: %v %+v", err, scs)
			}
		})
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestScanScenariosPropagatesReadError(t *testing.T) {
	want := errors.New("synthetic read failure")
	r := io.MultiReader(strings.NewReader("{\"id\":\"first\"}\n"), failingReader{want})
	scs, err := scanScenarios("broken.jsonl", r)
	if !errors.Is(err, want) || scs != nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("read failure not propagated: %v %+v", err, scs)
	}
}

func TestClopperPearsonBounds(t *testing.T) {
	near := func(got, want float64) bool { return got > want-1e-4 && got < want+1e-4 }
	// Design doc §11: 0/300 has a one-sided 95% upper bound of 1-0.05^(1/300).
	if u := cpUpper(0, 300); !near(u, 1-math.Pow(0.05, 1.0/300)) {
		t.Errorf("cpUpper(0,300) = %v", u)
	}
	// k=n: lower bound is 0.05^(1/n).
	if l := cpLower(100, 100); !near(l, math.Pow(0.05, 0.01)) {
		t.Errorf("cpLower(100,100) = %v", l)
	}
	// 90/100 is a 90% point estimate whose lower bound is well under 90%.
	if l := cpLower(90, 100); !(l > 0.83 && l < 0.85) {
		t.Errorf("cpLower(90,100) = %v", l)
	}
	if cpLower(0, 10) != 0 || cpUpper(10, 10) != 1 {
		t.Error("degenerate bounds")
	}
}

func TestActionSeparatesContentBlocksFromTechnicalRefusals(t *testing.T) {
	cases := []struct {
		r       result
		content bool
		tech    bool
	}{
		{result{Decision: policy.Deny, Action: "POLICY_DISALLOWED"}, true, false},
		{result{Decision: policy.Review, Action: "REVIEW_REQUIRED"}, true, false},
		{result{Decision: policy.Review, Action: "forward"}, false, false},
		{result{Decision: policy.Unavailable, Action: "GUARD_UNAVAILABLE"}, false, true},
		{result{Decision: policy.Unsupported, Action: "UNSUPPORTED_PROTOCOL"}, false, true},
		{result{Decision: "skipped"}, false, false},
	}
	for _, c := range cases {
		if contentBlocked(c.r) != c.content || technicalRefusal(c.r) != c.tech {
			t.Errorf("%+v: content=%v tech=%v", c.r, contentBlocked(c.r), technicalRefusal(c.r))
		}
	}
	if outcome(scenario{Expect: "review"}, result{Decision: policy.Review}) != "ok" ||
		outcome(scenario{Expect: "review"}, result{Decision: policy.Allow}) != "missed" ||
		outcome(scenario{Expect: "review"}, result{Decision: policy.Deny}) != "over_block" {
		t.Error("review expectation outcomes")
	}
}
