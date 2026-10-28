package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"riskguard/internal/audit"
)

func TestCoverageStatesReconcileAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	st, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ev := func(class, decision, reason, cov, covReason, userText, status string) audit.Event {
		return audit.Event{Timestamp: now, RouteClass: class, Decision: decision, ReasonCode: reason, Coverage: cov,
			CoverageReason: covReason, UserText: userText, ClassifierStatus: status}
	}
	for _, e := range []audit.Event{
		ev("model_text", "allow", "CLASSIFIER_SAFE", "full_selected_inputs", "", "complete", "ok"),
		// Partial because of history, but the latest user text itself was classified whole.
		ev("model_text", "allow", "CLASSIFIER_SAFE", "partial_context", "HISTORY_NOT_INSPECTED", "complete", "ok"),
		ev("model_text", "review", "AMBIGUOUS", "partial_context", "TRUNCATED", "truncated", "ok"),
		ev("model_text", "unavailable", "MODEL_TIMEOUT", "full_selected_inputs", "", "complete", "timeout"),
		ev("model_text", "unsupported", "NO_INSPECTABLE_INPUT", "unsupported", "", "absent", ""),
		ev("model_text", "unsupported", "PARSE_FAILED", "unsupported", "", "", ""),
		ev("model_uninspectable", "unsupported", "COVERAGE_GAP", "unsupported", "", "", ""),
		ev("model_text", "allow", "T0_ONLY_EXCEPTION", "t0_only", "", "", ""),
		ev("unknown", "unsupported", "APPROVED_EXCEPTION", "unsupported", "", "", ""),
		// Rejected before inspection: no coverage field, must still be counted.
		ev("model_text", "unavailable", "ADMISSION_LIMIT", "", "", "", ""),
		ev("model_text", "unavailable", "SPOOL_FULL", "", "", "", ""),
		// Not model requests: never part of coverage.
		ev("admin_passthrough", "reject", "BODY_TOO_LARGE", "", "", "", ""),
		ev("read_passthrough", "passthrough", "", "", "", "", ""),
	} {
		st.Add(e)
	}
	check := func(c CoverageSummary) {
		t.Helper()
		want := map[string]int{CovFull: 2, CovPartial: 2, CovUnsupported: 3, CovExempt: 2, CovNotReached: 2}
		total := 0
		for k, n := range want {
			if c.States[k] != n {
				t.Errorf("state %s = %d, want %d (%v)", k, c.States[k], n, c.States)
			}
			total += n
		}
		if c.Tracked != total || len(c.States) != len(want) || c.Untracked != 1 {
			t.Errorf("tracked %d untracked %d states %v", c.Tracked, c.Untracked, c.States)
		}
		if c.UserText["complete"] != 3 || c.UserText["truncated"] != 1 || c.UserText["absent"] != 1 || c.UserTextOK != 2 {
			t.Errorf("user text %v ok=%d", c.UserText, c.UserTextOK)
		}
		reasons := map[string]int{}
		for _, r := range c.Reasons {
			reasons[r.Key] = r.Count
		}
		for _, k := range []string{"partial_context:HISTORY_NOT_INSPECTED", "partial_context:TRUNCATED",
			"unsupported:NO_INSPECTABLE_INPUT", "unsupported:COVERAGE_GAP", "not_inspected:ADMISSION_LIMIT",
			"exempt:T0_ONLY_EXCEPTION", "exempt:APPROVED_EXCEPTION"} {
			if reasons[k] != 1 {
				t.Errorf("reason %s = %d (%v)", k, reasons[k], reasons)
			}
		}
	}
	// The admin-route rejection is guarded but not a model request; it sits in a tracked minute,
	// so it is neither a coverage state nor untracked history.
	if c := st.Summary(time.Hour, time.Minute).Coverage; c.Untracked != 0 || c.Tracked != 11 {
		t.Fatalf("before legacy data: tracked %d untracked %d", c.Tracked, c.Untracked)
	}

	// A minute written by an older version has no coverage data: reported as untracked, not as gaps.
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var snap map[string]json.RawMessage
	json.Unmarshal(raw, &snap)
	var buckets []map[string]any
	json.Unmarshal(snap["buckets"], &buckets)
	buckets = append(buckets, map[string]any{"m": now.Unix()/60 - 5, "req": 4, "guarded": 1})
	snap["buckets"], _ = json.Marshal(buckets)
	raw, _ = json.Marshal(snap)
	os.WriteFile(path, raw, 0o600)

	reloaded, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	c := reloaded.Summary(time.Hour, time.Minute).Coverage
	check(c)
	if c.Since != now.Unix()/60 {
		t.Errorf("since %d, want the first tracked minute %d", c.Since, now.Unix()/60)
	}
}
