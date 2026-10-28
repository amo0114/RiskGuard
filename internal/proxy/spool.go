package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const spoolPrefix = "rg-spool-"
const DefaultSpoolMaxMemoryBytes int64 = 32 << 20
const spoolBufferBytes int64 = 32 << 10

var ErrSpoolFull = errors.New("spool budget exhausted")
var ErrSpoolIO = errors.New("spool storage failure")

// SpoolPool accounts for all request-body buffers (including disk scratch space) before
// allocating them. Disk bytes and file slots have independent aggregate budgets.
type SpoolPool struct {
	dir       string
	memLimit  int64
	maxTotal  int64
	maxFiles  int
	maxMemory int64

	mu     sync.Mutex
	used   int64
	files  int
	memory int64
}

type SpoolOption func(*SpoolPool)

func WithSpoolMemoryLimit(n int64) SpoolOption {
	return func(p *SpoolPool) { p.maxMemory = n }
}

// NewSpoolPool creates dir (0700) and deletes files left by a previous crash.
// WithSpoolMemoryLimit overrides the default aggregate RAM budget of 32 MiB.
func NewSpoolPool(dir string, memLimit, maxTotal int64, maxFiles int, options ...SpoolOption) (*SpoolPool, error) {
	p := &SpoolPool{dir: dir, memLimit: memLimit, maxTotal: maxTotal, maxFiles: maxFiles, maxMemory: DefaultSpoolMaxMemoryBytes}
	for _, option := range options {
		option(p)
	}
	if memLimit < 0 || maxTotal < 0 || maxFiles < 0 || p.maxMemory <= 0 {
		return nil, errors.New("invalid spool budget")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	stale, _ := filepath.Glob(filepath.Join(dir, spoolPrefix+"*"))
	for _, f := range stale {
		os.Remove(f)
	}
	return p, nil
}

func (p *SpoolPool) reserve(n int64, newFile bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > p.maxTotal-p.used || (newFile && p.files >= p.maxFiles) {
		return false
	}
	p.used += n
	if newFile {
		p.files++
	}
	return true
}

func (p *SpoolPool) release(n int64, hadFile bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used -= n
	if hadFile {
		p.files--
	}
}

func (p *SpoolPool) reserveMemory(n int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > p.maxMemory-p.memory {
		return false
	}
	p.memory += n
	return true
}

func (p *SpoolPool) releaseMemory(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.memory -= n
}

// Usage returns bytes reserved on disk and reserved spool file slots.
func (p *SpoolPool) Usage() (int64, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used, p.files
}

// MemoryUsage returns live buffer capacity and the aggregate RAM budget, not process RSS.
func (p *SpoolPool) MemoryUsage() (int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.memory, p.maxMemory
}

type Spool struct {
	p              *SpoolPool
	mem            [][]byte
	memSize        int64
	memoryReserved int64
	f              *os.File
	fileSlot       bool // a slot can exist even if CreateTemp failed
	fileSize       int64
	reserved       int64
	rest           io.Reader  // unread remainder when a budget ran out
	closeMu        sync.Mutex // Close runs from the handler and from the upstream transport
}

const spoolChunk = 1 << 20

// Read consumes body into a Spool. On ErrSpoolFull the returned Spool is still usable for
// forwarding (Forward replays what was read, then the remainder) but not for inspection.
// Other errors return nil and release every reservation. Local storage errors wrap ErrSpoolIO.
func (p *SpoolPool) Read(body io.Reader) (*Spool, error) {
	s := &Spool{p: p}
	for s.memSize < p.memLimit {
		size := spoolBufferBytes
		if len(s.mem) == 0 {
			size = 4 << 10 // small requests do not reserve the entire per-request threshold
		}
		size = min(size, p.memLimit-s.memSize)
		if !p.reserveMemory(size) {
			s.rest = body
			return s, ErrSpoolFull
		}
		s.memoryReserved += size
		buf := make([]byte, size)
		n, err := readSpoolBuffer(body, buf)
		s.mem = append(s.mem, buf[:n])
		s.memSize += int64(n)
		if err == io.EOF {
			return s, nil
		}
		if err != nil {
			s.Close()
			return nil, err
		}
	}

	if !p.reserveMemory(spoolBufferBytes) {
		s.rest = body
		return s, ErrSpoolFull
	}
	buf := make([]byte, spoolBufferBytes)
	keepScratch := false
	defer func() {
		if !keepScratch {
			p.releaseMemory(spoolBufferBytes)
		}
	}()
	for {
		n, err := body.Read(buf)
		if err != nil && err != io.EOF {
			s.Close()
			return nil, err
		}
		if n > 0 {
			if s.fileSize+int64(n) > s.reserved {
				if !p.reserve(spoolChunk, !s.fileSlot) {
					// Keep this already-budgeted buffer alive for exact shadow replay.
					s.rest = io.MultiReader(bytes.NewReader(buf[:n]), body)
					s.memoryReserved += spoolBufferBytes
					keepScratch = true
					return s, ErrSpoolFull
				}
				s.reserved += spoolChunk
				s.fileSlot = true
				if s.f == nil {
					f, ferr := os.CreateTemp(p.dir, spoolPrefix+"*")
					if ferr != nil {
						s.Close()
						return nil, fmt.Errorf("%w: %w", ErrSpoolIO, ferr)
					}
					s.f = f
				}
			}
			written, werr := s.f.Write(buf[:n])
			if werr == nil && written != n {
				werr = io.ErrShortWrite
			}
			if werr != nil {
				s.Close()
				return nil, fmt.Errorf("%w: %w", ErrSpoolIO, werr)
			}
			s.fileSize += int64(n)
		}
		if err == io.EOF {
			return s, nil
		}
	}
}

// Unlike ReadFull, preserve an explicit ErrUnexpectedEOF from a broken HTTP upload.
func readSpoolBuffer(body io.Reader, buf []byte) (int, error) {
	n, empty := 0, 0
	for n < len(buf) {
		m, err := body.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
		if m == 0 {
			empty++
			if empty >= 100 {
				return n, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
	return n, nil
}

// Complete reports whether the whole body is buffered (inspection is possible).
func (s *Spool) Complete() bool { return s.rest == nil }

func (s *Spool) Size() int64 { return s.memSize + s.fileSize }

// Reader returns a fresh reader over the buffered bytes; callable any number of times.
func (s *Spool) Reader() io.Reader {
	readers := make([]io.Reader, 0, len(s.mem)+1)
	for _, chunk := range s.mem {
		readers = append(readers, bytes.NewReader(chunk))
	}
	if s.f != nil {
		readers = append(readers, io.NewSectionReader(s.f, 0, s.fileSize))
	}
	return io.MultiReader(readers...)
}

// Inspection reads only local buffers/files. Preserve its I/O error separately because the
// protocol extractor intentionally folds read failures into an unsupported-input result.
type spoolInspectionReader struct {
	io.Reader
	err error
}

func (r *spoolInspectionReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

// Forward returns the exact original byte stream for the upstream request. The spool is released
// as soon as the transport has read the whole body (or closes it), not when the response ends:
// agent requests carry megabytes of context and then stream for minutes, and holding their
// buffers that long would exhaust the pool. Nothing may read the spool after Forward.
func (s *Spool) Forward() io.ReadCloser {
	r := s.Reader()
	if s.rest != nil {
		r = io.MultiReader(r, s.rest)
	}
	return &releasingBody{r: r, s: s}
}

type releasingBody struct {
	r io.Reader
	s *Spool
}

func (b *releasingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil {
		b.s.Close() // the final bytes are already copied into p
	}
	return n, err
}

func (b *releasingBody) Close() error {
	b.s.Close()
	return nil
}

// Close deletes the temp file and returns all budgets. Safe to call more than once and
// concurrently; a Forward reader still running afterwards gets a read error, never stale budget.
func (s *Spool) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.f != nil {
		name := s.f.Name()
		s.f.Close()
		os.Remove(name)
		s.f = nil
	}
	s.p.release(s.reserved, s.fileSlot)
	s.reserved, s.fileSlot = 0, false
	s.mem, s.rest = nil, nil
	s.p.releaseMemory(s.memoryReserved)
	s.memoryReserved, s.memSize = 0, 0
}
