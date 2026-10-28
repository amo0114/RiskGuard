package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"riskguard/internal/audit"
)

func covEvent(at time.Time, class, decision, reason, cov, covReason, userText, status string) audit.Event {
	return audit.Event{Timestamp: at, RouteClass: class, Decision: decision, ReasonCode: reason, Coverage: cov,
		CoverageReason: covReason, UserText: userText, ClassifierStatus: status}
}

func TestCoverageStatesReconcile(t *testing.T) {
	st, _ := NewStats("")
	now := time.Now()
	ev := func(class, decision, reason, cov, covReason, userText, status string) audit.Event {
		return covEvent(now, class, decision, reason, cov, covReason, userText, status)
	}
	for _, e := range []audit.Event{
		ev("model_text", "allow", "CLASSIFIER_SAFE", "full_selected_inputs", "", "complete", "ok"),
		// Partial because of history, but the latest user text itself was classified whole.
		ev("model_text", "allow", "CLASSIFIER_SAFE", "partial_context", "HISTORY_NOT_INSPECTED", "complete", "ok"),
		ev("model_text", "review", "AMBIGUOUS", "partial_context", "TRUNCATED", "truncated", "ok"),
		// Input extracted whole, classifier timed out: full coverage, but no effective classification.
		ev("model_text", "unavailable", "MODEL_TIMEOUT", "full_selected_inputs", "", "complete", "timeout"),
		ev("model_text", "unsupported", "NO_INSPECTABLE_INPUT", "unsupported", "", "absent", ""),
		ev("model_text", "unsupported", "PARSE_FAILED", "unsupported", "", "", ""),
		ev("model_uninspectable", "unsupported", "COVERAGE_GAP", "unsupported", "", "", ""),
		ev("model_text", "allow", "T0_ONLY_EXCEPTION", "t0_only", "", "", ""),
		ev("unknown", "unsupported", "APPROVED_EXCEPTION", "unsupported", "", "", ""),
		// Rejected before inspection: no coverage field, must still be counted.
		ev("model_text", "unavailable", "ADMISSION_LIMIT", "", "", "", ""),
		ev("model_text", "unavailable", "SPOOL_FULL", "", "", "", ""),
		// Not model requests: never part of coverage, never reported as legacy either.
		ev("admin_passthrough", "reject", "BODY_TOO_LARGE", "", "", "", ""),
		ev("read_passthrough", "passthrough", "", "", "", "", ""),
	} {
		st.Add(e)
	}
	c := st.Summary(time.Hour, time.Minute).Coverage
	want := map[string]int{CovFull: 2, CovPartial: 2, CovUnsupported: 3, CovExempt: 2, CovNotReached: 2}
	total := 0
	for k, n := range want {
		if c.States[k] != n {
			t.Errorf("state %s = %d, want %d (%v)", k, c.States[k], n, c.States)
		}
		total += n
	}
	if c.Tracked != total || len(c.States) != len(want) || c.LegacyUnknown != 0 {
		t.Errorf("tracked %d legacy %d states %v", c.Tracked, c.LegacyUnknown, c.States)
	}
	// The timeout counts as complete user text but not as an effective classification.
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

// A minute holding only a current non-model rejection has no coverage states; that must not be
// read as old data without coverage.
func TestCoverageNonModelOnlyMinuteIsNotLegacy(t *testing.T) {
	st, _ := NewStats("")
	st.Add(covEvent(time.Now(), "admin_passthrough", "reject", "BODY_TOO_LARGE", "", "", "", ""))
	if c := st.Summary(time.Hour, time.Minute).Coverage; c.Tracked != 0 || c.LegacyUnknown != 0 || c.Since != 0 {
		t.Errorf("non-model only: %+v", c)
	}
}

// Disabled mode forwards model requests as passthrough: no review ran, so nothing is counted
// (the console shows coverage as not computed rather than as zero gaps).
func TestCoverageDisabledModeCountsNothing(t *testing.T) {
	st, _ := NewStats("")
	st.Add(covEvent(time.Now(), "model_text", "passthrough", "", "", "", "", ""))
	if c := st.Summary(time.Hour, time.Minute).Coverage; c.Tracked != 0 || c.LegacyUnknown != 0 || len(c.States) != 0 {
		t.Errorf("disabled: %+v", c)
	}
}

// Upgrading mid-minute: the old version's events in the current minute keep their unknown status
// while new events in the same minute are counted, and the migration runs only once.
func TestCoverageLegacyMinuteMigratedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	now := time.Now()
	cur := now.Unix() / 60
	legacy := []map[string]any{
		{"m": cur - 5, "req": 4, "guarded": 3}, // an older minute
		{"m": cur, "req": 120, "guarded": 100}, // the minute the upgrade happens in
	}
	raw, _ := json.Marshal(map[string]any{"buckets": legacy, "events": []any{}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Add(covEvent(now, "model_text", "allow", "CLASSIFIER_SAFE", "full_selected_inputs", "", "complete", "ok"))
	st.Add(covEvent(now, "admin_passthrough", "reject", "BODY_TOO_LARGE", "", "", "", ""))
	check := func(label string, c CoverageSummary) {
		t.Helper()
		if c.Tracked != 1 || c.States[CovFull] != 1 || c.LegacyUnknown != 103 || c.Since != cur {
			t.Errorf("%s: tracked %d full %d legacy %d since %d (want 1/1/103/%d)", label, c.Tracked,
				c.States[CovFull], c.LegacyUnknown, c.Since, cur)
		}
	}
	check("after upgrade", st.Summary(time.Hour, time.Minute).Coverage)

	// Persist and reload: the current minute now holds 102 guarded events, but only the 100 from
	// before the upgrade stay unknown.
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	check("after restart", reloaded.Summary(time.Hour, time.Minute).Coverage)
}
