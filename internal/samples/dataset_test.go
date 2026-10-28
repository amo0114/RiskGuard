package samples

import (
	"testing"
	"time"
)

func TestLabeledUsesLatestReviewAndCountsTheRest(t *testing.T) {
	cfg := testConfig(t.TempDir())
	st, err := Open(cfg, encKey, dedupKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t0 := time.Now()
	for _, tr := range []string{"rg-a", "rg-b", "rg-c", "rg-d"} {
		collectAt(t, st, t0, tr, "text of "+tr)
	}
	review := func(trace string, sup int64, in ReviewInput) int64 {
		t.Helper()
		in.Supersedes = sup
		id, err := st.AddReview(occ(t, st, trace).ID, "alice", "p1", in)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// a: relabeled; only the latest label counts.
	first := review("rg-a", 0, ReviewInput{Status: "labeled", ExpectedAction: "deny"})
	review("rg-a", first, ReviewInput{Status: "labeled", ExpectedAction: "allow", Category: "Jailbreak", Reason: "fine"})
	// b: labeled, then disputed: out.
	first = review("rg-b", 0, ReviewInput{Status: "labeled", ExpectedAction: "deny"})
	review("rg-b", first, ReviewInput{Status: "disputed"})
	// c: labeled, text deleted afterwards keeps no reviews; d: never reviewed.
	review("rg-c", 0, ReviewInput{Status: "labeled", ExpectedAction: "review"})
	if err := st.Delete(occ(t, st, "rg-c").ID); err != nil {
		t.Fatal(err)
	}

	got, skipped, err := st.Labeled()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("labeled = %+v", got)
	}
	a := got[0]
	if a.Text != "text of rg-a" || a.ExpectedAction != "allow" || a.Category != "Jailbreak" || a.Reason != "fine" ||
		!a.Random || a.Protocol != "openai_chat" || a.ReviewPolicy != "p1" || a.ContentHMAC == "" {
		t.Errorf("item = %+v", a)
	}
	if len(skipped) != 1 || skipped["disputed"] != 1 {
		t.Errorf("skipped = %v", skipped)
	}

	// Reviews outlive text: an expired text is counted, never exported.
	st.now = func() time.Time { return t0.Add(cfg.ContentRetention + time.Hour) }
	got, skipped, err = st.Labeled()
	if err != nil || len(got) != 0 || skipped["text_expired"] != 1 {
		t.Errorf("after expiry: %v %v %v", got, skipped, err)
	}
}
