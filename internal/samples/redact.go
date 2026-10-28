package samples

import (
	"regexp"
	"strings"
)

// redactionVersion changes whenever a rule changes, so stored text records which rules shaped it.
const redactionVersion = 3

// maxRedactions: text dense with secrets is more likely a credential dump than a question, and
// what survives redaction would not be reviewable anyway, so the text is not kept.
const maxRedactions = 50

type rule struct {
	kind string
	re   *regexp.Regexp
	repl string // may reference groups; the secret itself is never kept
	// unclosed, checked right after this rule, finds an opening the rule could not complete.
	// Such text is not stored: guessing where the secret ends would keep part of it.
	unclosed *regexp.Regexp
	reason   string
}

const secretFieldPrefix = `(?i)\b([\w.-]*(?:password|passwd|pwd|passphrase|secret|(?:api|access|secret|private)[_-]?key|token|auth)["']?\s*[:=]\s*)`

// Go regexps are RE2 (linear time), so hostile input cannot make redaction blow up.
var rules = []rule{
	// Checked before any field rule can erase only the BEGIN line of an unterminated
	// PRIVATE_KEY=... assignment and leave the key body behind.
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), "[REDACTED_PRIVATE_KEY]",
		regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`), "UNCLOSED_PRIVATE_KEY"},
	{"bearer", regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`), "${1}[REDACTED_TOKEN]", nil, ""},
	{"api_key", regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})`), "[REDACTED_API_KEY]", nil, ""},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "[REDACTED_JWT]", nil, ""},
	{"url_credentials", regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@`), "${1}[REDACTED_CREDENTIALS]@", nil, ""},
	// Triple-quoted values first (they may span lines): otherwise the quoted form below matches
	// their empty leading "" and leaves the secret after it.
	{"secret_field", regexp.MustCompile(secretFieldPrefix + `(?:"""[\s\S]*?"""|'''[\s\S]*?''')`), "${1}[REDACTED_SECRET]",
		regexp.MustCompile(secretFieldPrefix + `(?:"""|''')`), "UNCLOSED_SECRET_FIELD"},
	// The name may carry any identifier prefix (DB_PASSWORD, mysql_root_password: '_' is a word
	// character, so \b alone misses them). The value is a whole quoted string, or else the rest of
	// the line (passwords may contain spaces; over-redacting a line is the safe side). A value
	// starting with '=' is code ("token := f()", "token == x"), not an assignment of a secret.
	// Consume escapes as pairs so an escaped quote cannot end a quoted secret early. A quote
	// still right after a field name afterwards means the value never closed.
	{"secret_field", regexp.MustCompile(secretFieldPrefix + `(?:"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*'|[^\s"'=][^\r\n]*)`), "${1}[REDACTED_SECRET]",
		regexp.MustCompile(secretFieldPrefix + `["']`), "UNCLOSED_SECRET_FIELD"},
	{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), "[REDACTED_EMAIL]", nil, ""},
	{"phone", regexp.MustCompile(`\b1[3-9]\d{9}\b`), "[REDACTED_PHONE]", nil, ""},
}

// redact replaces known secret shapes with type placeholders. A non-empty exclude means the text
// must not be stored at all (an unterminated key block/quoted secret, or too many hits).
// It cannot find every secret; content permissions and encryption still apply.
func redact(s string) (out string, hits map[string]int, exclude string) {
	hits = map[string]int{}
	for _, r := range rules {
		n := 0
		s = r.re.ReplaceAllStringFunc(s, func(m string) string {
			out := r.re.ReplaceAllString(m, r.repl)
			if out != m { // an earlier placeholder matching again is not a new secret
				n++
			}
			return out
		})
		if n > 0 {
			hits[r.kind] += n // several rules may share a kind
		}
		if r.unclosed != nil && r.unclosed.MatchString(s) {
			return "", hits, r.reason
		}
	}
	total := 0
	for _, n := range hits {
		total += n
	}
	if total > maxRedactions {
		return "", hits, "TOO_MANY_SECRETS"
	}
	return strings.ToValidUTF8(s, "\uFFFD"), hits, ""
}
