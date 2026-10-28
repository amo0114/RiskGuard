package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoolAggregateMemoryConfiguration(t *testing.T) {
	dir := t.TempDir()
	key := write(t, dir, "key", strings.Repeat("x", 32))
	raw, err := os.ReadFile("../../config/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	base := strings.NewReplacer("/etc/riskguard/guard.key", key, "/etc/riskguard/hmac.key", key, "/etc/riskguard/console.token", key).Replace(string(raw))
	for _, tc := range []struct {
		name, field string
		valid       bool
		want        int64
	}{
		{"omitted default", "", true, 32 << 20},
		{"explicit", "  spool_max_memory_bytes: 2097152\n", true, 2 << 20},
		{"zero default", "  spool_max_memory_bytes: 0\n", true, 32 << 20},
		{"negative", "  spool_max_memory_bytes: -1\n", false, 0},
		{"insufficient", "  spool_max_memory_bytes: 1048576\n", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(base, "  spool_max_memory_bytes: 33554432     # 32 MiB across all request buffers, including disk scratch\n", tc.field, 1)
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, _, err := Load(path)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid RAM budget accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Request.SpoolMaxMemoryBytes != tc.want {
				t.Fatalf("RAM budget=%d want=%d", cfg.Request.SpoolMaxMemoryBytes, tc.want)
			}
		})
	}
}
