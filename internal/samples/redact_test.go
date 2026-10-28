package samples

import (
	"strings"
	"testing"
)

// Synthetic secrets only; none of these are real credentials.
func TestRedact(t *testing.T) {
	cases := []struct {
		in, secret, kind string
	}{
		{"use key sk-abcdefghijklmnop1234 please", "sk-abcdefghijklmnop1234", "api_key"},
		{"Authorization: Bearer abc.def-ghi_jkl123", "abc.def-ghi_jkl123", "bearer"},
		{"aws AKIAABCDEFGHIJKLMNOP x", "AKIAABCDEFGHIJKLMNOP", "api_key"},
		{"ghp_" + strings.Repeat("a", 36), strings.Repeat("a", 36), "api_key"},
		{"dsn postgres://admin:hunter22@db:5432/x", "hunter22", "url_credentials"},
		{`{"password": "s3cr3t-pass"}`, "s3cr3t-pass", "secret_field"},
		{"API_KEY=zzzzyyyyxxxx", "zzzzyyyyxxxx", "secret_field"},
		{"mail me at a.b@example.com", "a.b@example.com", "email"},
		{"call 13812345678", "13812345678", "phone"},
		{"jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4", "jwt"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow", "private_key"},
	}
	for _, c := range cases {
		out, hits, excl := redact(c.in)
		if excl != "" || strings.Contains(out, c.secret) || hits[c.kind] == 0 {
			t.Errorf("%q -> %q hits=%v exclude=%q", c.in, out, hits, excl)
		}
	}
	// Secret fields: any length, spaces inside the value, quoted or not.
	for _, c := range []struct{ in, secret string }{
		{"PASSWORD=abc", "abc"},
		{`password: "correct horse battery"`, "horse battery"},
		{"pwd = my secret pass phrase", "pass phrase"},
		{"db_password='a b'", "a b"},
		{`{"api_key":"x"}`, `"x"`},
		{"MYSQL_ROOT_PASSWORD=hunter2", "hunter2"},
		{"aws_secret_key: AbCd/1234", "AbCd"},
		{`{"password":"alpha\"beta gamma"}`, "beta gamma"},
		{`PASSWORD="alpha\"beta gamma"`, "beta gamma"},
		{`password='alpha\'beta gamma'`, "beta gamma"},
		{`PASSWORD="alpha\\"`, "alpha"},
		{`secret = """abc def"""`, "abc def"},
		{`password = '''hunter2'''`, "hunter2"},
		{"token = \"\"\"line one\nline two\"\"\"", "line two"},
	} {
		if out, hits, _ := redact(c.in); strings.Contains(out, c.secret) || hits["secret_field"] != 1 {
			t.Errorf("%q -> %q", c.in, out)
		}
	}
	for _, in := range []string{`PASSWORD = """multi`, `secret = '''x`} {
		if out, _, excl := redact(in); excl != "UNCLOSED_SECRET_FIELD" || out != "" {
			t.Errorf("unclosed triple quote kept: %q -> %q %q", in, out, excl)
		}
	}
	// Code that merely mentions these words is not an assignment of a secret.
	for _, code := range []string{"token := next()", `if token == "" {`, "auth == nil", "max_tokens: 1024", "authors: Ann"} {
		if out, hits, _ := redact(code); out != code || len(hits) != 0 {
			t.Errorf("code changed: %q -> %q", code, out)
		}
	}
	if out, hits, _ := redact("write a quicksort in Go"); out != "write a quicksort in Go" || len(hits) != 0 {
		t.Errorf("plain text changed: %q %v", out, hits)
	}
	if out, _, excl := redact("here: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk"); excl != "UNCLOSED_PRIVATE_KEY" || out != "" {
		t.Errorf("unclosed key kept: %q %q", out, excl)
	}
	for _, in := range []string{
		`{"password":"alpha\"beta gamma`,
		`PASSWORD="alpha\`,
		"password='alpha\nbeta'",
	} {
		if out, _, excl := redact(in); excl != "UNCLOSED_SECRET_FIELD" || out != "" {
			t.Errorf("incomplete quoted secret kept: %q %q", out, excl)
		}
	}
	if out, _, excl := redact("PRIVATE_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk"); excl != "UNCLOSED_PRIVATE_KEY" || out != "" {
		t.Errorf("unclosed key assignment kept: %q %q", out, excl)
	}
	if _, _, excl := redact(strings.Repeat("x@example.com ", maxRedactions+1)); excl != "TOO_MANY_SECRETS" {
		t.Errorf("dense secrets kept: %q", excl)
	}
}
