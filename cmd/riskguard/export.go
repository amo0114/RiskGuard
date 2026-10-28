package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"riskguard/internal/samples"
)

// datasetItem is an rgeval scenario plus the label provenance. Only the redacted text the
// classifier saw leaves the store; trace, IP, credential and client stay behind.
type datasetItem struct {
	ID             string         `json:"id"`
	Group          string         `json:"group"`
	Split          string         `json:"split"`
	Protocol       string         `json:"protocol"`
	Expect         string         `json:"expect"`
	Body           map[string]any `json:"body"`
	ExpectedAction string         `json:"expected_action"`
	Category       string         `json:"category,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Source         map[string]any `json:"source"`
}

var expectOf = map[string]string{"allow": "allow", "review": "review", "deny": "block"}

// exportDataset freezes every labeled sample into dir (created 0700, files 0600): scenarios.jsonl
// in the rgeval format and manifest.json. The copy has no TTL; deleting it is the operator's job.
func exportDataset(st *samples.Store, dir string, now time.Time) (int, error) {
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%s already exists; export into a new directory", dir)
	}
	texts, skipped, err := st.Labeled()
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	count := func(m map[string]map[string]int, k, v string) {
		if m[k] == nil {
			m[k] = map[string]int{}
		}
		m[k][v]++
	}
	dist := map[string]map[string]int{}
	var lines []byte
	for _, t := range texts {
		// The content HMAC is keyed, so this id is stable across exports and reveals nothing.
		sum := sha256.Sum256([]byte("riskguard-dataset-item:" + t.ContentHMAC))
		split := "dev"
		if sum[0]&1 == 1 {
			split = "test"
		}
		group := "samples-enriched"
		if t.Random {
			group = "samples-random"
		}
		it := datasetItem{
			ID: "rg-" + hex.EncodeToString(sum[:8]), Group: group, Split: split, Protocol: "openai_chat",
			Expect: expectOf[t.ExpectedAction], ExpectedAction: t.ExpectedAction, Category: t.Category, Reason: t.Reason,
			Body: map[string]any{"model": "eval", "messages": []map[string]string{{"role": "user", "content": t.Text}}},
			Source: map[string]any{"store": "riskguard-samples", "original_protocol": t.Protocol, "truncated": t.Truncated,
				"redaction_version": t.RedactionVersion, "review_id": t.ReviewID, "review_policy": t.ReviewPolicy},
		}
		b, err := json.Marshal(it)
		if err != nil {
			return 0, err
		}
		lines = append(append(lines, b...), '\n')
		count(dist, "expected_action", t.ExpectedAction)
		count(dist, "split", split)
		count(dist, "group", group)
		count(dist, "review_policy", t.ReviewPolicy)
		count(dist, "original_protocol", t.Protocol)
		count(dist, "redaction_version", fmt.Sprint(t.RedactionVersion))
		if t.Category != "" {
			count(dist, "category", t.Category)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "scenarios.jsonl"), lines, 0o600); err != nil {
		return 0, err
	}
	sum := sha256.Sum256(lines)
	notes := []string{
		"Labels are the latest human review per text; classifier decisions are not included and are not ground truth.",
		"Text is the redacted classifier input re-wrapped as one openai_chat user message, not the original request (exact_reproduction=false).",
		"One item per distinct pre-redaction text; near-duplicates and same-task follow-ups are not grouped into families, so they can cross splits.",
		"samples-random came from the random baseline; samples-enriched only from review/deny/unavailable/unsupported traffic. Report them separately.",
		"No TTL: this copy outlives the 7-day sample store. It contains real user text; delete it when the evaluation is done.",
	}
	m := map[string]any{
		"dataset_version": "rg-samples-" + now.UTC().Format("20060102T150405Z"), "generated_at": now.UTC().Format(time.RFC3339),
		"items": len(texts), "distribution": dist, "excluded": skipped,
		"split_rule": "sha256(item key)[0] odd = test, even = dev", "exact_reproduction": false,
		"files": map[string]string{"scenarios.jsonl": hex.EncodeToString(sum[:])}, "notes": notes,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return 0, err
	}
	return len(texts), os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o600)
}
