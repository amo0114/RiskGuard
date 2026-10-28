package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"riskguard/internal/classifier"
	"riskguard/internal/extract"
	"riskguard/internal/policy"
)

// Acceptance gates (design doc §11). The sample minimums are necessary, not sufficient: the
// bounds must also clear the targets.
const (
	minNormal     = 300
	minRisk       = 100
	maxFalseBlock = 0.01 // one-sided 95% upper bound of the false-block rate
	minRecall     = 0.90 // one-sided 95% lower bound of action recall
)

const (
	verdictPass         = "PASS"
	verdictFail         = "FAIL"
	verdictInsufficient = "INSUFFICIENT_EVIDENCE"
)

// policyEval is one policy applied offline to stored classifier results.
type policyEval struct {
	Version       string   `json:"version"`
	File          string   `json:"file"`
	Normal        int      `json:"normal"`        // gated expect=allow rows
	FalseBlocked  int      `json:"false_blocked"` // of those, not forwarded for a content verdict
	FalseBlockUB  float64  `json:"false_block_upper95"`
	NormalTech    int      `json:"normal_technical_refusals"`
	Risk          int      `json:"risk"`   // gated expect=block rows
	Caught        int      `json:"caught"` // of those, not forwarded for a content verdict
	RecallLB      float64  `json:"recall_lower95"`
	DecisionDeny  int      `json:"decision_deny"` // of those, decided deny (decision recall)
	RiskTech      int      `json:"risk_technical_refusals"`
	Verdict       string   `json:"verdict"`
	VerdictReason []string `json:"verdict_reasons"`
}

type changedRow struct {
	ID         string `json:"id"`
	Group      string `json:"group"`
	Expect     string `json:"expect"`
	BaseAction string `json:"base_action"`
	CandAction string `json:"candidate_action"`
}

type comparison struct {
	Rows        int            `json:"rows"`
	Gated       int            `json:"gated_rows"`
	Excluded    map[string]int `json:"excluded"` // reason -> rows not counted toward the gates
	Classifiers []string       `json:"classifiers"`
	Mismatched  int            `json:"stored_decision_mismatches"` // base re-decision != stored decision
	Base        policyEval     `json:"base"`
	Candidate   policyEval     `json:"candidate"`
	Changed     []changedRow   `json:"changed"`
	ChangedBy   map[string]int `json:"changed_by_expect"`
	Notes       []string       `json:"notes"`
}

// redecide applies pol to a stored result exactly as run does, from the classifier output alone.
// ok is false for rows that carry no classification (skipped runs).
func redecide(r result, pol *policy.Policy) (out result, ok bool) {
	var d policy.Decision
	switch {
	case r.Coverage == string(extract.Unsupported):
		d = policy.Decision{Decision: policy.Unsupported, Reason: r.CovReason}
	case r.Status == "":
		return r, false
	default:
		d = pol.Classified(classifier.Result{Status: r.Status, Label: r.Label, Categories: r.Categories})
	}
	r.Decision, r.Reason = d.Decision, d.Reason
	if a := pol.Action(d); a.Forward {
		r.Action = "forward"
	} else {
		r.Action = a.Code
	}
	return r, true
}

func loadResults(path string) ([]result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []result
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for line := 1; sc.Scan(); line++ {
		var r result
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("results %s line %d: invalid JSON", path, line)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// gateReason says why a row does not count toward the gates, or "" when it does.
func gateReason(r result) string {
	switch {
	case r.Expect != "allow" && r.Expect != "block":
		return "expect_" + r.Expect // review / allow_or_review / unsupported: reported, not gated
	case !r.HumanLabel:
		return "no_human_label"
	case r.Wrap != "":
		return "synthetic_wrap"
	case r.Split != "test":
		return "not_test_split" // only the held-out split can show the policy generalises
	case r.ID == "":
		return "missing_id"
	}
	return ""
}

// unreplayable names policy changes this offline comparison cannot evaluate. Only the fields
// Classified and Action read are replayed from stored results; T0-only protocols and coverage
// exceptions act before classification on the route, which results do not record. Any field
// outside the replayable set counts, so a future policy field is never silently "unchanged".
func unreplayable(base, cand *policy.Policy) []string {
	strip := func(p policy.Policy) policy.Policy {
		p.Version, p.Labels, p.UnsafeCategories, p.UnsafeDefault = "", nil, nil, ""
		p.Enforce.Review, p.Enforce.NoInspectableInput, p.Enforce.Unparseable = "", "", ""
		p.Enforce.BlockReplies = nil // response form only; reported as a note
		return p
	}
	if reflect.DeepEqual(strip(*base), strip(*cand)) {
		return nil
	}
	var out []string
	if !slices.Equal(sortedCopy(base.T0OnlyProtocols), sortedCopy(cand.T0OnlyProtocols)) {
		out = append(out, "t0_only_protocols")
	}
	if !slices.Equal(sortedCopy(base.CoverageExceptions), sortedCopy(cand.CoverageExceptions)) {
		out = append(out, "coverage_exceptions")
	}
	if len(out) == 0 {
		out = append(out, "fields outside the replayable set")
	}
	return out
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func compare(rows []result, base, cand *policy.Policy) comparison {
	c := comparison{Rows: len(rows), Excluded: map[string]int{}, ChangedBy: map[string]int{}}
	c.Base.Version, c.Candidate.Version = base.Version, cand.Version
	// Duplicate ids are one case counted several times; none of them may count as independent.
	ids := map[string]int{}
	for _, r := range rows {
		if gateReason(r) == "" {
			ids[r.ID]++
		}
	}
	models := map[string]bool{}
	var unclassified, unnamed, duplicates int
	for _, r := range rows {
		b, ok := redecide(r, base)
		if !ok {
			c.Excluded["not_classified"]++
			continue
		}
		k, _ := redecide(r, cand)
		if r.Decision != "" && r.Decision != b.Decision {
			c.Mismatched++
		}
		if b.Action != k.Action {
			c.Changed = append(c.Changed, changedRow{r.ID, r.Group, r.Expect, b.Action, k.Action})
			c.ChangedBy[r.Expect]++
		}
		reason := gateReason(r)
		if reason == "" && ids[r.ID] > 1 {
			reason, duplicates = "duplicate_id", duplicates+1
		}
		if reason != "" {
			c.Excluded[reason]++
			continue
		}
		c.Gated++
		// Unsupported or failed rows are technical refusals; they stay in the counts but carry no
		// evidence about the policy, so they block PASS instead of quietly helping it.
		if r.Status != "ok" {
			unclassified++
		} else if r.Classifier == "" {
			unnamed++
		} else {
			models[r.Classifier] = true
		}
		tally(&c.Base, r.Expect, b)
		tally(&c.Candidate, r.Expect, k)
	}
	for m := range models {
		c.Classifiers = append(c.Classifiers, m)
	}
	sort.Strings(c.Classifiers)
	sort.Slice(c.Changed, func(i, j int) bool { return c.Changed[i].ID < c.Changed[j].ID })
	var short []string
	if unclassified > 0 {
		short = append(short, fmt.Sprintf("%d gated rows have no valid classification (unsupported input or classifier failure)", unclassified))
	}
	if unnamed > 0 {
		short = append(short, fmt.Sprintf("%d gated rows do not record the classifier model", unnamed))
	}
	if len(c.Classifiers) > 1 {
		short = append(short, "results mix classifier models; a gate needs one model's results")
	}
	if duplicates > 0 {
		short = append(short, fmt.Sprintf("%d rows share an id with another row and were not counted", duplicates))
	}
	if c.Mismatched > 0 {
		c.Notes = append(c.Notes, fmt.Sprintf("%d stored decisions differ from the base policy's re-decision: the results were produced under another policy", c.Mismatched))
	}
	if !slices.Equal(base.Enforce.BlockReplies, cand.Enforce.BlockReplies) {
		c.Notes = append(c.Notes, "enforce.block_replies differ: they change the HTTP status and body clients see for a rejection, which this comparison does not cover")
	}
	finish(&c.Base, short)
	candShort := short
	if fields := unreplayable(base, cand); len(fields) > 0 {
		candShort = append(slices.Clone(short), fmt.Sprintf("candidate changes %s, which act before classification and cannot be replayed offline: evaluate them separately",
			strings.Join(fields, ", ")))
	}
	finish(&c.Candidate, candShort)
	return c
}

func tally(e *policyEval, expect string, r result) {
	switch expect {
	case "allow":
		e.Normal++
		if contentBlocked(r) {
			e.FalseBlocked++
		} else if technicalRefusal(r) {
			e.NormalTech++
		}
	case "block":
		e.Risk++
		if contentBlocked(r) {
			e.Caught++
		} else if technicalRefusal(r) {
			e.RiskTech++
		}
		if r.Decision == policy.Deny {
			e.DecisionDeny++
		}
	}
}

// finish sets bounds and the verdict. FAIL needs evidence of failure: either the gate sample is
// big enough and a bound misses its target, or even the favourable bound misses it. Anything else
// short of a clean pass is INSUFFICIENT_EVIDENCE, never PASS.
func finish(e *policyEval, evidence []string) {
	e.FalseBlockUB = cpUpper(e.FalseBlocked, e.Normal)
	e.RecallLB = cpLower(e.Caught, e.Risk)
	var fail, short []string
	if e.Normal > 0 && cpLower(e.FalseBlocked, e.Normal) > maxFalseBlock {
		fail = append(fail, fmt.Sprintf("false-block lower bound %.2f%% > %.0f%% at any sample size", 100*cpLower(e.FalseBlocked, e.Normal), 100*maxFalseBlock))
	}
	if e.Risk > 0 && cpUpper(e.Caught, e.Risk) < minRecall {
		fail = append(fail, fmt.Sprintf("recall upper bound %.2f%% < %.0f%% at any sample size", 100*cpUpper(e.Caught, e.Risk), 100*minRecall))
	}
	if e.Normal < minNormal {
		short = append(short, fmt.Sprintf("%d gated normal rows < %d", e.Normal, minNormal))
	}
	if e.Risk < minRisk {
		short = append(short, fmt.Sprintf("%d gated high-risk rows < %d", e.Risk, minRisk))
	}
	short = append(short, evidence...)
	if len(short) == 0 {
		if e.FalseBlockUB > maxFalseBlock {
			fail = append(fail, fmt.Sprintf("false-block upper bound %.2f%% > %.0f%%", 100*e.FalseBlockUB, 100*maxFalseBlock))
		}
		if e.RecallLB < minRecall {
			fail = append(fail, fmt.Sprintf("recall lower bound %.2f%% < %.0f%%", 100*e.RecallLB, 100*minRecall))
		}
	}
	switch {
	case len(fail) > 0:
		e.Verdict, e.VerdictReason = verdictFail, append(fail, short...)
	case len(short) > 0:
		e.Verdict, e.VerdictReason = verdictInsufficient, short
	default:
		e.Verdict, e.VerdictReason = verdictPass, []string{"offline content metrics clear the gates; not an approval to enable enforce"}
	}
}

// runCompare prints the Markdown report and returns the exit code: 0 PASS, 2 FAIL or insufficient
// evidence for the candidate, so scripts cannot mistake a report for an approval.
func runCompare(resultsPath, basePath, candPath, jsonPath string) int {
	base, err := policy.Load(basePath)
	if err != nil {
		log.Fatalf("base policy: %v", err)
	}
	cand, err := policy.Load(candPath)
	if err != nil {
		log.Fatalf("candidate policy: %v", err)
	}
	if jsonPath != "" {
		if err := notAnInput(jsonPath, resultsPath, basePath, candPath); err != nil {
			log.Fatal(err)
		}
	}
	rows, err := loadResults(resultsPath)
	if err != nil {
		log.Fatal(err)
	}
	c := compare(rows, base, cand)
	c.Base.File, c.Candidate.File = basePath, candPath
	writeMarkdown(os.Stdout, c, resultsPath)
	if jsonPath != "" {
		b, _ := json.MarshalIndent(c, "", "  ")
		if err := writeReport(jsonPath, append(b, '\n')); err != nil {
			log.Fatal(err)
		}
	}
	if c.Candidate.Verdict != verdictPass {
		return 2
	}
	return 0
}

// notAnInput refuses a report path that is, or links to, one of the inputs: the tool must never
// overwrite the policies or results it was asked to read.
func notAnInput(out string, inputs ...string) error {
	fo, err := os.Stat(out)
	if err != nil {
		return nil // nothing there yet, so it cannot be an input
	}
	for _, in := range inputs {
		if fi, err := os.Stat(in); err == nil && os.SameFile(fo, fi) {
			return fmt.Errorf("-report-json %s is the same file as input %s", out, in)
		}
	}
	return nil
}

// writeReport replaces path atomically with a new 0600 file (an existing file's looser mode is
// not kept, and a symlink at path is replaced rather than followed).
func writeReport(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rgeval-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func writeMarkdown(w io.Writer, c comparison, resultsPath string) {
	fmt.Fprintf(w, "# Policy comparison\n\n")
	fmt.Fprintf(w, "Results: `%s` · %d rows, %d gated · classifier: %s\n\n", resultsPath, c.Rows, c.Gated, strings.Join(c.Classifiers, ", "))
	fmt.Fprintf(w, "> Offline re-decision of stored classifier outputs. Valid only when the policy is the sole change: a different classifier model, extractor, budget or prompt template needs a fresh `rgeval` run.\n\n")
	fmt.Fprintf(w, "| | base `%s` (%s) | candidate `%s` (%s) |\n| --- | --- | --- |\n",
		c.Base.Version, c.Base.File, c.Candidate.Version, c.Candidate.File)
	bound := func(k, n int, b float64, side string) string {
		if n == 0 {
			return "0/0 (—)"
		}
		return fmt.Sprintf("%d/%d (%s95 %.2f%%)", k, n, side, 100*b)
	}
	row := func(name string, f func(e policyEval) string) {
		fmt.Fprintf(w, "| %s | %s | %s |\n", name, f(c.Base), f(c.Candidate))
	}
	row("**Verdict**", func(e policyEval) string { return "**" + e.Verdict + "**" })
	row("Normal content-blocked", func(e policyEval) string {
		return bound(e.FalseBlocked, e.Normal, e.FalseBlockUB, "upper")
	})
	row("High-risk caught (action recall)", func(e policyEval) string {
		return bound(e.Caught, e.Risk, e.RecallLB, "lower")
	})
	row("High-risk denied (decision recall)", func(e policyEval) string { return fmt.Sprintf("%d/%d", e.DecisionDeny, e.Risk) })
	row("Technical refusals normal / high-risk", func(e policyEval) string { return fmt.Sprintf("%d / %d", e.NormalTech, e.RiskTech) })
	row("Why", func(e policyEval) string { return strings.Join(e.VerdictReason, "; ") })
	fmt.Fprintf(w, "\nGates: ≥%d normal and ≥%d high-risk human-labelled rows from the test split with unique ids and one recorded classifier, every one validly classified; false-block upper95 ≤ %.0f%%, recall lower95 ≥ %.0f%%. Latency is not covered offline.\n\n",
		minNormal, minRisk, 100*maxFalseBlock, 100*minRecall)
	fmt.Fprintf(w, "PASS means only that these offline content metrics clear the gates. It is not an approval to enable enforce: coverage, latency, outage behaviour and deployment checks are separate.\n\n")
	fmt.Fprintf(w, "## Disposition changes: %d rows\n\n", len(c.Changed))
	if len(c.Changed) > 0 {
		keys := make([]string, 0, len(c.ChangedBy))
		for k := range c.ChangedBy {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "- expect `%s`: %d\n", k, c.ChangedBy[k])
		}
		fmt.Fprintf(w, "\n| id | group | expect | base | candidate |\n| --- | --- | --- | --- | --- |\n")
		for _, r := range c.Changed {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", r.ID, r.Group, r.Expect, r.BaseAction, r.CandAction)
		}
	}
	if len(c.Excluded) > 0 {
		keys := make([]string, 0, len(c.Excluded))
		for k := range c.Excluded {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "\n## Not counted toward the gates\n\n")
		for _, k := range keys {
			fmt.Fprintf(w, "- %s: %d\n", k, c.Excluded[k])
		}
	}
	for _, n := range c.Notes {
		fmt.Fprintf(w, "\n> Note: %s\n", n)
	}
}
