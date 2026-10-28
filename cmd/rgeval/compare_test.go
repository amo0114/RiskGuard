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
		{ID: "nosplit", Expect: "allow", HumanLabel: true, Coverage: "full_selected_inputs", Status: "ok", Label: "Controversial"},
		{ID: "unlabelled", Expect: "allow", Coverage: "full_selected_inputs", Status: "ok", Label: "Controversial"},
		{ID: "wrapped", Expect: "block", HumanLabel: true, Wrap: "preapproved", Coverage: "full_selected_inputs", Status: "ok", Label: "Safe"},
		{ID: "rev", Expect: "review", HumanLabel: true, Coverage: "full_selected_inputs", Status: "ok", Label: "Controversial"},
		{ID: "skipped", Expect: "allow", HumanLabel: true, Coverage: "full_selected_inputs", Decision: "skipped"},
	}
	c := compare(append(rs, extra...), base, base)
	want := map[string]int{"not_test_split": 2, "no_human_label": 1, "synthetic_wrap": 1, "expect_review": 1, "not_classified": 1}
	for k, n := range want {
		if c.Excluded[k] != n {
			t.Errorf("excluded %s = %d (%v)", k, c.Excluded[k], c.Excluded)
		}
	}
	if c.Gated != 400 || c.Base.Verdict != verdictPass {
		t.Errorf("gated %d verdict %s %v", c.Gated, c.Base.Verdict, c.Base.VerdictReason)
	}
}

// Review blocker 01: rows the classifier never judged must not make a candidate pass, even when
// they look like zero false blocks.
func TestCompareUnclassifiedRowsBlockPass(t *testing.T) {
	base := basePolicy(t)
	rs := rows(0, 0, 100)
	for i := 0; i < 300; i++ {
		rs = append(rs, result{ID: fmt.Sprintf("u%d", i), Expect: "allow", HumanLabel: true, Split: "test",
			Coverage: "unsupported", CovReason: "MEDIA_ONLY"})
	}
	c := compare(rs, base, base)
	if c.Base.Verdict == verdictPass || c.Base.Normal != 300 || c.Base.FalseBlocked != 0 || c.Base.NormalTech != 300 {
		t.Errorf("all-unsupported normals: %s normal %d fb %d tech %d", c.Base.Verdict, c.Base.Normal, c.Base.FalseBlocked, c.Base.NormalTech)
	}
	// One unsupported row among otherwise valid ones is already enough to withhold PASS.
	rs = append(rows(300, 0, 100), result{ID: "media", Expect: "allow", HumanLabel: true, Split: "test",
		Coverage: "unsupported", CovReason: "MEDIA_ONLY"})
	if c := compare(rs, base, base); c.Base.Verdict != verdictInsufficient {
		t.Errorf("one unsupported row: %s", c.Base.Verdict)
	}
}

// Review blocker 02: only the test split, a recorded classifier and unique ids count.
func TestCompareAdmission(t *testing.T) {
	base := basePolicy(t)
	rs := rows(300, 0, 100)
	for i := range rs {
		rs[i].Split = ""
	}
	if c := compare(rs, base, base); c.Gated != 0 || c.Excluded["not_test_split"] != 400 || c.Base.Verdict == verdictPass {
		t.Errorf("no split: gated %d %v %s", c.Gated, c.Excluded, c.Base.Verdict)
	}

	rs = rows(300, 0, 100)
	for i := range rs {
		rs[i].Classifier = ""
	}
	if c := compare(rs, base, base); c.Base.Verdict != verdictInsufficient {
		t.Errorf("no classifier id: %s", c.Base.Verdict)
	}

	// One normal and one risky case repeated: 2 distinct cases, not 400.
	rs = rows(300, 0, 100)
	for i := range rs {
		rs[i].ID = rs[i].Expect
	}
	c := compare(rs, base, base)
	if c.Gated != 0 || c.Excluded["duplicate_id"] != 400 || c.Base.Verdict != verdictInsufficient {
		t.Errorf("duplicates: gated %d %v %s", c.Gated, c.Excluded, c.Base.Verdict)
	}
	// The same case in dev and in the held-out test split: a leak, so the test copy cannot count.
	rs = rows(300, 0, 100)
	dup := rs[0]
	dup.Split = "dev"
	if c := compare(append(rs, dup), base, base); c.Excluded["duplicate_id"] != 1 || c.Excluded["not_test_split"] != 1 ||
		c.Base.Verdict == verdictPass || c.Candidate.Verdict == verdictPass {
		t.Errorf("cross-split duplicate: %v %s", c.Excluded, c.Candidate.Verdict)
	}
	rs = append(rows(300, 0, 100), rows(1, 0, 0)...) // n0 twice
	if c := compare(rs, base, base); c.Excluded["duplicate_id"] != 2 || c.Base.Verdict != verdictInsufficient {
		t.Errorf("one duplicate pair: %v %s", c.Excluded, c.Base.Verdict)
	}
}

// Review blocker 03: changes that act before classification cannot be replayed and never PASS.
func TestCompareUnreplayablePolicyChanges(t *testing.T) {
	base := basePolicy(t)
	for name, edit := range map[string]func(string) string{
		"coverage exception": func(s string) string {
			return strings.Replace(s, "coverage_exceptions: []", "coverage_exceptions: [images]", 1)
		},
		"t0 protocol": func(s string) string {
			return strings.Replace(s, "  - rerank\n", "  - rerank\n  - moderations\n", 1)
		},
	} {
		cand := loadPolicy(t, edit)
		c := compare(rows(300, 0, 100), base, cand)
		if c.Base.Verdict != verdictPass || c.Candidate.Verdict != verdictInsufficient ||
			!strings.Contains(strings.Join(c.Candidate.VerdictReason, ";"), "cannot be replayed") {
			t.Errorf("%s: base %s candidate %s %v", name, c.Base.Verdict, c.Candidate.Verdict, c.Candidate.VerdictReason)
		}
	}
	// Reordering a list changes nothing.
	reordered := loadPolicy(t, func(s string) string {
		return strings.Replace(s, "  - embeddings\n  - rerank\n", "  - rerank\n  - embeddings\n", 1)
	})
	if c := compare(rows(300, 0, 100), base, reordered); c.Candidate.Verdict != verdictPass {
		t.Errorf("reordered t0 list: %s %v", c.Candidate.Verdict, c.Candidate.VerdictReason)
	}
	// Block replies change only the response form: noted, not a reason to withhold PASS.
	replies := loadPolicy(t, func(s string) string {
		return strings.Replace(s, "  unparseable: reject", "  unparseable: reject\n  block_replies: [\"blocked\"]", 1)
	})
	c := compare(rows(300, 0, 100), base, replies)
	if c.Candidate.Verdict != verdictPass || len(c.Notes) == 0 || !strings.Contains(c.Notes[0], "block_replies") {
		t.Errorf("block replies: %s %v", c.Candidate.Verdict, c.Notes)
	}
}

// Review blocker 04: the report must never overwrite an input, whatever path names it.
func TestReportPathNeverOverwritesInputs(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "candidate.yaml")
	res := filepath.Join(dir, "results.jsonl")
	os.WriteFile(pol, []byte("policy"), 0o644)
	os.WriteFile(res, []byte("{}\n"), 0o644)
	link := filepath.Join(dir, "link.json")
	os.Symlink(pol, link)
	hard := filepath.Join(dir, "hard.json")
	os.Link(res, hard)
	for _, out := range []string{pol, res, link, hard, filepath.Join(dir, ".", "candidate.yaml")} {
		if err := notAnInput(out, res, "base.yaml", pol); err == nil {
			t.Errorf("%s accepted as report path", out)
		}
	}
	if b, _ := os.ReadFile(pol); string(b) != "policy" {
		t.Error("input changed")
	}
	// A fresh path is fine; an existing unrelated 0644 report is replaced with a 0600 file.
	report := filepath.Join(dir, "report.json")
	os.WriteFile(report, []byte("old"), 0o644)
	if err := notAnInput(report, res, pol); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(report, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(report)
	if b, _ := os.ReadFile(report); string(b) != "new" || fi.Mode().Perm() != 0o600 {
		t.Errorf("report %q mode %v", b, fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".rgeval-report-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
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
