package proxy

import "testing"

func TestClientAndModelLabels(t *testing.T) {
	for ua, want := range map[string]string{
		"codex-tui/0.164.0 (Ubuntu 22.4.0; x86_64) WindowsTerminal": "codex-tui/0.164.0",
		"claude-cli/2.0.14 (external, cli)":                         "claude-cli/2.0.14",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)":                 "browser",
		"curl":               "curl",
		"evil<script>/1.0\n": "evilscript/1.0",
		"":                   "",
	} {
		if got := clientOf(ua); got != want {
			t.Errorf("clientOf(%q) = %q want %q", ua, got, want)
		}
	}
	for _, c := range []struct{ body, path, want string }{
		{"gpt-5.1-codex", "/v1/responses", "gpt-5.1-codex"},
		{"", "/v1beta/models/gemini-2.5-pro:streamGenerateContent", "gemini-2.5-pro"},
		{"", "/v1/chat/completions", ""},
		{"a b\"c", "/v1/chat/completions", "abc"},
	} {
		if got := modelOf(c.body, c.path); got != c.want {
			t.Errorf("modelOf(%q, %q) = %q want %q", c.body, c.path, got, c.want)
		}
	}
}
