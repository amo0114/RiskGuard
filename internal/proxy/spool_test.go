package proxy

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSpoolMemoryAndFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, spoolPrefix+"stale"), []byte("x"), 0o600)
	p, err := NewSpoolPool(dir, 1<<10, 8<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, spoolPrefix+"*")); len(left) != 0 {
		t.Fatal("stale spool not cleaned on start")
	}

	small := []byte("small body")
	s, err := p.Read(bytes.NewReader(small))
	if err != nil || s.f != nil || !s.Complete() {
		t.Fatalf("small: %v", err)
	}
	if b, _ := io.ReadAll(s.Forward()); !bytes.Equal(b, small) {
		t.Fatal("small forward differs")
	}
	s.Close()

	big := make([]byte, 3<<20+17)
	rand.Read(big)
	s, err = p.Read(bytes.NewReader(big))
	if err != nil || s.f == nil {
		t.Fatalf("big: %v", err)
	}
	st, _ := os.Stat(s.f.Name())
	if st.Mode().Perm() != 0o600 {
		t.Errorf("spool file mode %v", st.Mode().Perm())
	}
	for i := 0; i < 2; i++ { // inspect, then forward: both see the identical bytes
		if b, _ := io.ReadAll(s.Reader()); !bytes.Equal(b, big) {
			t.Fatal("reader differs")
		}
	}
	if s.Size() != int64(len(big)) {
		t.Fatalf("size %d", s.Size())
	}
	name := s.f.Name()
	if b, _ := io.ReadAll(s.Forward()); !bytes.Equal(b, big) {
		t.Fatal("forward differs")
	}
	// Reading the body to EOF already released it; later Close calls are no-ops.
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Error("spool file not removed after forward")
	}
	if used, files := p.Usage(); used != 0 || files != 0 {
		t.Errorf("budget leaked: %d bytes, %d files", used, files)
	}
	s.Close()
	s.Close()
}

func TestSpoolBudgetExhaustedStillForwardsExactly(t *testing.T) {
	p, _ := NewSpoolPool(t.TempDir(), 1<<10, 2<<20, 4)
	big := make([]byte, 5<<20)
	rand.Read(big)
	s, err := p.Read(bytes.NewReader(big))
	if !errors.Is(err, ErrSpoolFull) || s.Complete() {
		t.Fatalf("expected ErrSpoolFull, got %v", err)
	}
	if b, _ := io.ReadAll(s.Forward()); !bytes.Equal(b, big) {
		t.Fatal("replay after budget exhaustion differs")
	}
	s.Close()
	if used, files := p.Usage(); used != 0 || files != 0 {
		t.Errorf("budget leaked: %d %d", used, files)
	}
}

func TestSpoolFileLimitAndBodyLimit(t *testing.T) {
	p, _ := NewSpoolPool(t.TempDir(), 16, 64<<20, 1)
	a, err := p.Read(bytes.NewReader(make([]byte, 100)))
	if err != nil {
		t.Fatal(err)
	}
	if partial, err := p.Read(bytes.NewReader(make([]byte, 100))); !errors.Is(err, ErrSpoolFull) {
		t.Errorf("second file should exceed maxFiles: %v", err)
	} else {
		partial.Close()
	}
	a.Close()

	rec := httptest.NewRecorder()
	body := http.MaxBytesReader(rec, io.NopCloser(bytes.NewReader(make([]byte, 1000))), 500)
	var mbe *http.MaxBytesError
	if s, err := p.Read(body); s != nil || !errors.As(err, &mbe) {
		t.Errorf("over-limit body: %v", err)
	}
	if used, files := p.Usage(); used != 0 || files != 0 {
		t.Errorf("budget leaked after error: %d %d", used, files)
	}
}
