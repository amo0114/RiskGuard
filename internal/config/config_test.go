package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	key := write(t, dir, "k", strings.Repeat("x", 32))
	gkey := write(t, dir, "g", "guard-key")
	base := map[string]string{
		"listener":         `"127.0.0.1:4100"`,
		"admin_listener":   `"127.0.0.1:4101"`,
		"new_api_upstream": `"http://127.0.0.1:4000"`,
		"mode":             `"shadow"`,
		"hmac_key_file":    `"` + key + `"`,
	}
	render := func(over map[string]string) string {
		var b strings.Builder
		for k, v := range base {
			if o, ok := over[k]; ok {
				v = o
			}
			if v != "" {
				b.WriteString(k + ": " + v + "\n")
			}
		}
		b.WriteString("request:\n  max_body_bytes: 52428800\n  memory_spool_threshold_bytes: 1048576\n  spool_dir: " + dir + "/spool\n" +
			"  spool_max_total_bytes: 268435456\n  spool_max_files: 8\n  extract_concurrency: 2\n  extract_queue: 4\n" +
			"  primary_budget_bytes: 3072\n  context_budget_bytes: 1024\n")
		if _, ok := over["model_guard"]; !ok {
			b.WriteString("model_guard:\n  endpoint: \"http://127.0.0.1:8088\"\n  model: m\n  api_key_file: " + gkey +
				"\n  timeout: 8s\n  max_concurrency: 2\n  max_tokens: 128\n")
		}
		b.WriteString("policy_file: /p.yaml\n")
		return b.String()
	}
	if _, _, err := Load(write(t, dir, "ok.yaml", render(nil))); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	guard := func(attempt string) string {
		return "model_guard:\n  endpoint: \"http://127.0.0.1:8088\"\n  model: m\n  api_key_file: " + gkey +
			"\n  timeout: 8s\n  attempt_timeout: " + attempt + "\n  max_concurrency: 2\n  max_tokens: 128"
	}
	if _, _, err := Load(write(t, dir, "attempt.yaml", render(map[string]string{"model_guard": "", "mode": "\"shadow\"\n" + guard("4s")}))); err != nil {
		t.Fatalf("attempt_timeout 4s with timeout 8s rejected: %v", err)
	}
	bad := map[string]map[string]string{
		"public listener":     {"listener": `"0.0.0.0:4100"`},
		"remote upstream":     {"new_api_upstream": `"http://10.0.0.5:4000"`},
		"upstream with path":  {"new_api_upstream": `"http://127.0.0.1:4000/v1"`},
		"https upstream":      {"new_api_upstream": `"https://127.0.0.1:4000"`},
		"public classifier":   {"model_guard": "", "mode": "\"shadow\"\nmodel_guard:\n  endpoint: \"http://8.8.8.8:8088\"\n  model: m\n  api_key_file: x\n  timeout: 8s\n  max_concurrency: 2\n  max_tokens: 128"},
		"hostname classifier": {"model_guard": "", "mode": "\"shadow\"\nmodel_guard:\n  endpoint: \"http://guard.example.com:8088\"\n  model: m\n  api_key_file: x\n  timeout: 8s\n  max_concurrency: 2\n  max_tokens: 128"},
		"unknown mode":        {"mode": `"audit"`},
		"attempt >= timeout":  {"model_guard": "", "mode": "\"shadow\"\n" + guard("8s")},
		"negative attempt":    {"model_guard": "", "mode": "\"shadow\"\n" + guard("-1s")},
		"same admin listener": {"admin_listener": `"127.0.0.1:4100"`},
		"short hmac key":      {"hmac_key_file": `"` + write(t, dir, "short", "abc") + `"`},
		"unknown field":       {"mode": "\"shadow\"\ntarget_url: \"http://evil\""},
	}
	for name, over := range bad {
		if _, _, err := Load(write(t, dir, "bad.yaml", render(over))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	aux := func(mode, endpoint, keyFile string) map[string]string {
		return map[string]string{"mode": `"` + mode + `"` + "\naux_judge:\n  endpoint: \"" + endpoint + "\"\n  model: jevos-v5\n" +
			"  api_key_file: " + keyFile + "\n  timeout: 2s\n  max_concurrency: 1"}
	}
	_, sec, err := Load(write(t, dir, "aux.yaml", render(aux("shadow", "http://127.0.0.1:8017", gkey))))
	if err != nil || sec.AuxJudgeKey != "guard-key" {
		t.Fatalf("valid aux_judge: %v", err)
	}
	for name, over := range map[string]map[string]string{
		"aux in enforce":       aux("enforce", "http://127.0.0.1:8017", gkey),
		"aux public endpoint":  aux("shadow", "http://8.8.8.8:8017", gkey),
		"aux hosted endpoint":  aux("shadow", "https://api.example.com", gkey),
		"aux missing key file": aux("shadow", "http://127.0.0.1:8017", dir+"/missing"),
	} {
		if _, _, err := Load(write(t, dir, "bad.yaml", render(over))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
