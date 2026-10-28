package proxy

import "strings"

// clientOf keeps only the product token of a User-Agent ("codex-tui/0.164.0 (Ubuntu 22.4.0; ...)"
// -> "codex-tui/0.164.0"): enough to tell tools apart without OS, terminal or host details.
func clientOf(ua string) string {
	tok, _, _ := strings.Cut(strings.TrimSpace(ua), " ")
	name, ver, _ := strings.Cut(tok, "/")
	name = strings.ToLower(clean(name, 32, ""))
	switch {
	case name == "":
		return ""
	case name == "mozilla":
		return "browser"
	}
	if ver = clean(ver, 24, ""); ver != "" {
		return name + "/" + ver
	}
	return name
}

// modelOf is the requested model: the body's "model", or for Gemini the path segment
// (/v1beta/models/gemini-2.5-pro:generateContent). Client-controlled, so it is cut and filtered.
func modelOf(body, path string) string {
	if body == "" {
		if _, rest, ok := strings.Cut(path, "/models/"); ok {
			body, _, _ = strings.Cut(rest, ":")
		}
	}
	return clean(body, 64, ":/@")
}

// clean drops every byte outside [A-Za-z0-9._+-] (plus extra) and caps the length.
func clean(s string, max int, extra string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._+-"+extra, c) >= 0 {
			b.WriteByte(c)
		}
	}
	return b.String()
}
