package samples

import (
	"strings"
	"testing"
)

// Exercise persistence as well as the redactor: incomplete secret values must
// produce metadata-only samples, while complete escaped values remain reviewable.
func TestQuotedSecretCapture(t *testing.T) {
	for _, tc := range []struct {
		name, text, status, exclude string
	}{
		{"escaped_quote", `{"password":"alpha\"beta gamma","task":"refactor"}`, "stored", ""},
		{"incomplete_quote", `{"password":"alpha\"beta gamma`, "excluded", "UNCLOSED_SECRET_FIELD"},
		{"incomplete_key_assignment", "PRIVATE_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-key-material", "excluded", "UNCLOSED_PRIVATE_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t.TempDir())
			cfg.MaxTextBytes = 4096
			st := collect(t, cfg, func(c *Collector) {
				c.Offer(c.Candidate(tc.text, false), ev("quoted-secret", "allow"))
			})
			list, err := st.List(Filter{})
			if err != nil || len(list) != 1 {
				t.Fatalf("sample list: %v; count %d", err, len(list))
			}
			d, err := st.Get(list[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if d.ContentStatus != tc.status || d.ExcludeReason != tc.exclude {
				t.Fatalf("status %q, exclusion %q", d.ContentStatus, d.ExcludeReason)
			}
			if tc.exclude != "" {
				if d.Text != "" {
					t.Fatal("excluded sample exposes text")
				}
			} else if strings.Contains(d.Text, "alpha") || strings.Contains(d.Text, "beta gamma") ||
				!strings.Contains(d.Text, "[REDACTED_SECRET]") || !strings.Contains(d.Text, "refactor") {
				t.Fatal("quoted secret was incompletely redacted or unrelated task text was lost")
			}
		})
	}
}
