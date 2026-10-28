package audit

import (
	"errors"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// D07: an unwritable audit sink is counted and reported, never propagated to the request path.
func TestLogSurvivesWriterFailure(t *testing.T) {
	l := New(failingWriter{}, []byte("0123456789abcdef0123456789abcdef"))
	for i := 0; i < 3; i++ {
		l.Log(Event{TraceID: "t"})
	}
	if l.Failures() != 3 {
		t.Fatalf("failures = %d", l.Failures())
	}
}

func TestFingerprint(t *testing.T) {
	l := New(nil, []byte("0123456789abcdef0123456789abcdef"))
	a, b := l.Fingerprint("198.51.100.7"), l.Fingerprint("198.51.100.8")
	if len(a) != 16 || a == b || a == "198.51.100.7" || l.Fingerprint("") != "" {
		t.Fatalf("fingerprints %q %q", a, b)
	}
	if New(nil, []byte("another-key-another-key-another!")).Fingerprint("198.51.100.7") == a {
		t.Fatal("fingerprint does not depend on key")
	}
}
