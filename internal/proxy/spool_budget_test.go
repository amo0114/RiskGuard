package proxy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"riskguard/internal/extract"
)

func assertSpoolReleased(t *testing.T, p *SpoolPool) {
	t.Helper()
	memory, _ := p.MemoryUsage()
	disk, files := p.Usage()
	if memory != 0 || disk != 0 || files != 0 {
		t.Fatalf("spool reservations leaked: memory=%d disk=%d files=%d", memory, disk, files)
	}
}

func TestSpoolMemoryExhaustionReplaysAndRecovers(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		threshold, budget, disk int64
	}{
		{"before any read", 8192, 1, 1 << 20},
		{"after memory prefix", 8192, 4096, 1 << 20},
		{"before disk scratch", 16, 16, 1 << 20},
		{"disk full retains scratch", 16, 16 + spoolBufferBytes, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewSpoolPool(t.TempDir(), tc.threshold, tc.disk, 1, WithSpoolMemoryLimit(tc.budget))
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte("0123456789"), 1000)
			s, err := p.Read(bytes.NewReader(want))
			if !errors.Is(err, ErrSpoolFull) || s == nil || s.Complete() {
				t.Fatalf("partial spool: %v", err)
			}
			if used, limit := p.MemoryUsage(); used > limit {
				t.Fatalf("RAM over budget: %d > %d", used, limit)
			}
			if got, err := io.ReadAll(s.Forward()); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("partial replay changed body: %v", err)
			}
			s.Close()
			s.Close()
			assertSpoolReleased(t, p)
		})
	}
}

type pausedUpload struct{ entered, release chan struct{} }

func (r *pausedUpload) Read(b []byte) (int, error) {
	close(r.entered)
	<-r.release
	return copy(b, "body"), io.EOF
}

func TestSpoolReservesBeforeConcurrentSlowReads(t *testing.T) {
	p, err := NewSpoolPool(t.TempDir(), 8192, 1<<20, 1, WithSpoolMemoryLimit(8192))
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		spool *Spool
		err   error
	}
	done := make(chan result, 2)
	release := make(chan struct{})
	defer close(release)
	for i := 0; i < 2; i++ {
		r := &pausedUpload{entered: make(chan struct{}), release: release}
		go func() { s, err := p.Read(r); done <- result{s, err} }()
		<-r.entered
	}
	if used, limit := p.MemoryUsage(); used != 8192 || used != limit {
		t.Fatalf("upload buffers not accounted before read: %d / %d", used, limit)
	}
	want := []byte("third upload")
	s, err := p.Read(bytes.NewReader(want))
	if !errors.Is(err, ErrSpoolFull) || s == nil || s.Size() != 0 {
		t.Fatalf("third upload admitted: %v", err)
	}
	got, err := io.ReadAll(s.Forward())
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unread replay: %v", err)
	}
	s.Close()
	// Unblock exactly the two tiny local reads; no network or load generation.
	release <- struct{}{}
	release <- struct{}{}
	for i := 0; i < 2; i++ {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.spool.Close()
	}
	assertSpoolReleased(t, p)
	s, err = p.Read(bytes.NewReader([]byte("recovered")))
	if err != nil {
		t.Fatalf("RAM budget did not recover: %v", err)
	}
	s.Close()
	assertSpoolReleased(t, p)
}

func TestSpoolCreateFailureReleasesFileSlot(t *testing.T) {
	dir := t.TempDir()
	p, err := NewSpoolPool(dir, 16, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if s, err := p.Read(bytes.NewReader(make([]byte, 100))); s != nil || !errors.Is(err, ErrSpoolIO) {
			t.Fatalf("expected storage failure: %v", err)
		}
		assertSpoolReleased(t, p)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := p.Read(bytes.NewReader(make([]byte, 100)))
	if err != nil {
		t.Fatalf("file slot did not recover: %v", err)
	}
	s.Close()
	assertSpoolReleased(t, p)
}

type brokenUpload struct{}

func (brokenUpload) Read(b []byte) (int, error) { return copy(b, "broken"), io.ErrUnexpectedEOF }

func TestSpoolReadFailureReleasesMemory(t *testing.T) {
	for _, threshold := range []int64{0, 1024} {
		p, err := NewSpoolPool(t.TempDir(), threshold, 1<<20, 1)
		if err != nil {
			t.Fatal(err)
		}
		if s, err := p.Read(brokenUpload{}); s != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("broken upload treated as complete: %v", err)
		}
		assertSpoolReleased(t, p)
	}
}

func TestSpoolInspectionPreservesFileReadFailure(t *testing.T) {
	p, err := NewSpoolPool(t.TempDir(), 1, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Read(bytes.NewBufferString(chatBody("normal coding request")))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.f.Close(); err != nil {
		t.Fatal(err)
	}
	inspected := &spoolInspectionReader{Reader: s.Reader()}
	extract.Extract("openai_chat", "application/json", "", inspected, extract.Budget{Primary: 1024}, 1<<20)
	if inspected.err == nil {
		t.Fatal("local file read error lost during extraction")
	}
}
