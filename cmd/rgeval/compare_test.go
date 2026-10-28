package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"riskguard/internal/policy"
)

func loadPolicy(t *testing.T, edit func(string) string) *policy.Policy {
	t.Helper()
	raw, err := os.ReadFile("../../config/policy-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte(edit(string(raw))), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func basePolicy(t *testing.T) *policy.Policy {
	return loadPolicy(t, func(s string) string { return s })
}

// rows builds gated, human-labelled results: normal rows classify Safe (fp of them Controversial),
// risk rows classify Unsafe/Violent.
func rows(normal, fp, risk int) []result {
	var out []result
	for i := 0; i < normal; i++ {
		r := result{ID: fmt.Sprintf("n%d", i), Group: "g", Expect: "allow", HumanLabel: true, Split: "test",
			Coverage: "full_selected_inputs", Status: "ok", Label: "Safe", Classifier: "qg-8b"}
		if i < fp {
			r.Label = "Controversial"
		}
		out = append(out, r)
	}
	for i := 0; i < risk; i++ {
		out = append(out, result{ID: fmt.Sprintf("r%d", i), Group: "g", Expect: "block", HumanLabel: true, Split: "test",
			Coverage: "full_selected_inputs", Status: "ok", Label: "Unsafe", Categories: []string{"Violent"}, Classifier: "qg-8b"})
	}
	return out
}

func TestCompareRedecidesByActionNotStoredDecision(t *testing.T) {
	base := basePolicy(t)
	// Violent review -> deny: both reject in enforce (422 vs 403), so actions change but neither
	// forwards; decision recall moves while action recall does not.
	deny := loadPolicy(t, func(s string) string {
		return strings.Replace(s, `"Violent": review`, `"Violent": deny`, 1)
	})
	rs := rows(300, 0, 100)
	for i := range rs {
		rs[i].Decision = "bogus" // stored decisions must be ignored
	}
	c := compare(rs, base, deny)
	if c.Base.Caught != 100 || c.Candidate.Caught != 100 || c.Base.DecisionDeny != 0 || c.Candidate.DecisionDeny != 100 {
		t.Errorf("caught %d/%d deny %d/%d", c.Base.Caught, c.Candidate.Caught, c.Base.DecisionDeny, c.Candidate.DecisionDeny)
	}
	if c.ChangedBy["block"] != 100 || c.Changed[0].BaseAction != "REVIEW_REQUIRED" || c.Changed[0].CandAction != "POLICY_DISALLOWED" {
		t.Errorf("changed %v %+v", c.ChangedBy, c.Changed[0])
	}
	if c.Mismatched != 400 || len(c.Notes) == 0 {
		t.Errorf("stored-decision mismatch not reported: %d %v", c.Mismatched, c.Notes)
	}
	if c.Base.Verdict != verdictPass || c.Candidate.Verdict != verdictPass {
		t.Errorf("verdicts %s %s: %v %v", c.Base.Verdict, c.Candidate.Verdict, c.Base.VerdictReason, c.Candidate.VerdictReason)
	}
}

func TestCompareVerdicts(t *testing.T) {
	base := basePolicy(t)
	forward := loadPolicy(t, func(s string) string {
		return strings.Replace(s, "  review: reject", "  review: forward", 1)
	})

	// Enough rows, but forwarding review lets every Violent row through: FAIL, not "insufficient".
	c := compare(rows(300, 0, 100), base, forward)
	if c.Candidate.Verdict != verdictFail || c.Candidate.Caught != 0 || c.ChangedBy["block"] != 100 {
		t.Errorf("forward candidate: %s caught %d %v", c.Candidate.Verdict, c.Candidate.Caught, c.Candidate.VerdictReason)
	}

	// Minimums are necessary, not sufficient: 300 normal with 3 false blocks has upper95 > 1%.
	if c := compare(rows(300, 3, 100), base, base); c.Base.Verdict != verdictFail {
		t.Errorf("3/300 false blocks: %s %v", c.Base.Verdict, c.Base.VerdictReason)
	}

	// Too few rows and nothing conclusive: never PASS.
	if c := compare(rows(60, 0, 20), base, base); c.Base.Verdict != verdictInsufficient {
		t.Errorf("60/20 rows: %s", c.Base.Verdict)
	}

	// Few rows but already conclusive: 10 of 50 false blocks fails at any sample size.
	if c := compare(rows(50, 10, 0), base, base); c.Base.Verdict != verdictFail {
		t.Errorf("10/50 false blocks: %s %v", c.Base.Verdict, c.Base.VerdictReason)
	}

	// A failed classification among gated rows makes the evidence incomplete.
	rs := rows(300, 0, 100)
	rs[0].Status, rs[0].Label = "timeout", "Unknown"
	if c := compare(rs, base, base); c.Base.Verdict != verdictInsufficient || c.Base.NormalTech != 1 {
		t.Errorf("classifier timeout: %s tech %d %v", c.Base.Verdict, c.Base.NormalTech, c.Base.VerdictReason)
	}

	// Results from two classifier models cannot back one gate.
	rs = rows(300, 0, 100)
	rs[1].Classifier = "qg-0.6b"
	if c := compare(rs, base, base); c.Base.Verdict != verdictInsufficient || len(c.Classifiers) != 2 {
		t.Errorf("mixed models: %s %v", c.Base.Verdict, c.Classifiers)
	}
}

func TestCompareGateExclusions(t *testing.T) {
	base := basePolicy(t)
	rs := rows(300, 0, 100)
	extra := []result{
		{ID: "dev", Expect: "allow", HumanLabel: true, Split: "dev", Coverage: "full_selected_inputs", Status: "ok", Label: "Controversial"},
		{ID: "unlabelled", Expect: "allow", Coverage: "full_selected_inputs", Status: "ok", Label: "Controversial"},
		{ID: "wrapped", Expect: "block", HumanLabel: true, Wrap: "preapproved", Coverage: "full_selected_inputs", Status: "ok", Label: "Safe"},
		{ID: "rev", Expect: "review", HumanLabel: true, Coverage: "full_selected_inputs", Status: "ok", Label: "Controversial"},
		{ID: "skipped", Expect: "allow", HumanLabel: true, Coverage: "full_selected_inputs", Decision: "skipped"},
		// Unsupported rows carry no classifier status but are still re-decided from coverage.
		{ID: "media", Expect: "allow", HumanLabel: true, Coverage: "unsupported", CovReason: "MEDIA_ONLY"},
	}
	c := compare(append(rs, extra...), base, base)
	want := map[string]int{"dev_split": 1, "no_human_label": 1, "synthetic_wrap": 1, "expect_review": 1, "not_classified": 1}
	for k, n := range want {
		if c.Excluded[k] != n {
			t.Errorf("excluded %s = %d (%v)", k, c.Excluded[k], c.Excluded)
		}
	}
	// The media row is gated: a technical refusal on a normal request, not a content block.
	if c.Gated != 401 || c.Base.Normal != 301 || c.Base.FalseBlocked != 0 || c.Base.NormalTech != 1 {
		t.Errorf("gated %d normal %d fb %d tech %d", c.Gated, c.Base.Normal, c.Base.FalseBlocked, c.Base.NormalTech)
	}
	if c.Base.Verdict != verdictPass {
		t.Errorf("verdict %s %v", c.Base.Verdict, c.Base.VerdictReason)
	}
}

func TestCompareReportMentionsScope(t *testing.T) {
	base := basePolicy(t)
	var b strings.Builder
	writeMarkdown(&b, compare(rows(10, 0, 5), base, base), "results.jsonl")
	out := b.String()
	for _, want := range []string{"INSUFFICIENT_EVIDENCE", "Valid only when the policy is the sole change", "Latency is not covered"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}
