package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"riskguard/internal/audit"
)

type seen struct {
	method, requestURI, host string
	header                   http.Header
	bodySHA                  string
	bodyLen                  int
}

// mockNewAPI records what reached "New API" and serves a few behaviours by path.
type mockNewAPI struct {
	mu       sync.Mutex
	last     seen
	hits     atomic.Int32
	canceled chan struct{}
}

func (m *mockNewAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.hits.Add(1)
	h := sha256.New()
	n, _ := io.Copy(h, r.Body)
	m.mu.Lock()
	m.last = seen{r.Method, r.RequestURI, r.Host, r.Header.Clone(), hex.EncodeToString(h.Sum(nil)), int(n)}
	m.mu.Unlock()

	switch {
	case strings.HasPrefix(r.URL.Path, "/sse") || r.Header.Get("X-Mock") == "sse":
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Oneapi-Request-Id", "upstream-req-1")
		fl := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			select {
			case <-r.Context().Done():
				close(m.canceled)
				return
			case <-time.After(300 * time.Millisecond):
			}
			io.WriteString(w, "data: {\"i\":"+string(rune('0'+i))+"}\n\n")
			fl.Flush()
		}
		io.WriteString(w, "data: [DONE]\n\n")
	case r.URL.Path == "/ws":
		conn, brw, _ := http.NewResponseController(w).Hijack()
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Protocol: realtime\r\n\r\n")
		brw.Flush()
		buf := make([]byte, 64)
		for {
			n, err := brw.Read(buf)
			if err != nil {
				return
			}
			conn.Write(bytes.ToUpper(buf[:n]))
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, `{"error":{"message":"from new api","type":"new_api_error"}}`)
	}
}

type harness struct {
	up    *mockNewAPI
	guard *httptest.Server
	logs  *bytes.Buffer
	logMu *sync.Mutex
}

type lockedBuf struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func newHarness(t *testing.T, maxBody int64) *harness {
	return newHarnessMode(t, "disabled", maxBody, nil)
}

// newHarnessMode builds the Guard in front of a mock New API. g may be nil for disabled mode.
func newHarnessMode(t *testing.T, mode string, maxBody int64, g *Guard) *harness {
	t.Helper()
	up := &mockNewAPI{canceled: make(chan struct{})}
	upSrv := httptest.NewServer(up)
	t.Cleanup(upSrv.Close)
	u, _ := url.Parse(upSrv.URL)
	h := &harness{up: up, logs: &bytes.Buffer{}, logMu: &sync.Mutex{}}
	a := audit.New(lockedBuf{h.logMu, h.logs}, bytes.Repeat([]byte("k"), 32))
	h.guard = httptest.NewServer(New(u, Options{Mode: mode, MaxBody: maxBody, Audit: a, Guard: g}))
	t.Cleanup(h.guard.Close)
	return h
}

func (h *harness) logText() string { h.logMu.Lock(); defer h.logMu.Unlock(); return h.logs.String() }

// C01–C04: request line (incl. encoded path and query key), auth/business headers, body bytes,
// Host and the OpenResty-built forwarding chain reach New API unchanged; the response comes back
// unchanged, including New API's own error status/body.
func TestTransparentForwarding(t *testing.T) {
	for _, mode := range []string{"disabled", "shadow", "enforce"} {
		t.Run(mode, func(t *testing.T) { transparentForwarding(t, mode) })
	}
}

func transparentForwarding(t *testing.T, mode string) {
	var g *Guard
	if mode != "disabled" {
		g = testGuard(t, safeClassifier())
		// random bytes are not JSON: enforce would reject them, so let unparseable bodies through
		g.Policy.Enforce.Unparseable = "forward"
	}
	h := newHarnessMode(t, mode, 50<<20, g)
	body := make([]byte, 3<<20)
	rand.Read(body)
	want := sha256.Sum256(body)
	target := h.guard.URL + "/v1beta/models/gemini-x:generateContent/models/a%2Fb:streamGenerateContent?key=sk-query&alt=sse"
	req, _ := http.NewRequest("POST", target, bytes.NewReader(body))
	req.Host = "api.example.com"
	hdr := map[string]string{
		"Authorization":     "Bearer sk-bearer",
		"X-Api-Key":         "sk-claude",
		"X-Goog-Api-Key":    "sk-goog",
		"Anthropic-Version": "2023-06-01",
		"Anthropic-Beta":    "interleaved-thinking-2025-05-14",
		"Mj-Api-Secret":     "mj",
		"New-Api-User":      "1",
		"Accept-Encoding":   "gzip, br",
		"X-Real-IP":         "198.51.100.7",
		"X-Forwarded-For":   "203.0.113.9, 198.51.100.7",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "api.example.com",
		"Content-Type":      "application/json",
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set(TraceHeader, "client-forged")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	got := h.up.last
	if got.method != "POST" || got.requestURI != "/v1beta/models/gemini-x:generateContent/models/a%2Fb:streamGenerateContent?key=sk-query&alt=sse" {
		t.Errorf("request line changed: %s %s", got.method, got.requestURI)
	}
	if got.host != "api.example.com" {
		t.Errorf("host changed: %s", got.host)
	}
	for k, v := range hdr {
		if g := got.header.Values(k); len(g) != 1 || g[0] != v {
			t.Errorf("header %s: got %q want %q", k, g, v)
		}
	}
	if tr := got.header.Get(TraceHeader); !strings.HasPrefix(tr, "rg-") {
		t.Errorf("trace header not replaced: %q", tr)
	}
	if got.bodySHA != hex.EncodeToString(want[:]) || got.bodyLen != len(body) {
		t.Errorf("body changed: %d bytes", got.bodyLen)
	}
	if resp.StatusCode != http.StatusTeapot || resp.Header.Get("X-Upstream") != "yes" ||
		string(rb) != `{"error":{"message":"from new api","type":"new_api_error"}}` {
		t.Errorf("response changed: %d %q", resp.StatusCode, rb)
	}
	if resp.Header.Get(TraceHeader) == "" {
		t.Error("no trace header on response")
	}

	logs := h.logText()
	for _, secret := range []string{"sk-", "key=", "198.51.100.7", "203.0.113.9", "Bearer", "a%2Fb", "generateContent"} {
		if strings.Contains(logs, secret) {
			t.Errorf("audit log leaks %q: %s", secret, logs)
		}
	}
	var ev audit.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs)), &ev); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	// The model name is recorded on purpose (grouping), filtered and only in its own field.
	// disabled mode never inspects the request, so it has no model.
	if (ev.Phase != "disabled" && ev.Model != "gemini-x") || strings.Count(logs, "gemini-x") > 1 || strings.Contains(ev.PathTemplate, "gemini") {
		t.Errorf("model field: %q in %s", ev.Model, logs)
	}
	if ev.RouteClass != "model_text" || ev.Protocol != "gemini" || ev.HTTPStatus != 418 || ev.BodyBytes != int64(len(body)) || ev.SourceIPHMAC == "" {
		t.Errorf("audit event: %+v", ev)
	}
}

// SSE events must reach the client as they are produced, with the stream terminator intact.
func TestSSEIsNotBuffered(t *testing.T) {
	h := newHarness(t, 50<<20)
	start := time.Now()
	resp, err := http.Post(h.guard.URL+"/sse", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	var firstAt time.Duration
	var lines []string
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			if firstAt == 0 {
				firstAt = time.Since(start)
			}
			lines = append(lines, l)
		}
	}
	total := time.Since(start)
	if len(lines) != 6 || lines[5] != "data: [DONE]" {
		t.Fatalf("stream content: %q", lines)
	}
	if firstAt > 800*time.Millisecond || total < 1500*time.Millisecond {
		t.Errorf("first event at %v, total %v: stream was buffered", firstAt, total)
	}
	if resp.Header.Get("X-Oneapi-Request-Id") != "upstream-req-1" {
		t.Error("upstream request id header lost")
	}
}

// C09: a client that disconnects mid-stream cancels the New API request.
func TestClientCancelPropagates(t *testing.T) {
	h := newHarness(t, 50<<20)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", h.guard.URL+"/sse", strings.NewReader("{}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(resp.Body)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	cancel()
	resp.Body.Close()
	select {
	case <-h.up.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not observe cancellation")
	}
	time.Sleep(100 * time.Millisecond)
	if !strings.Contains(h.logText(), `"client_aborted":true`) {
		t.Errorf("abort not recorded: %s", h.logText())
	}
}

// C05: WebSocket upgrade is tunnelled with the auth subprotocol intact and frames flow both ways.
// This is transport only; it does not inspect frames.
func TestWebSocketTunnel(t *testing.T) {
	h := newHarness(t, 50<<20)
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.guard.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: gw.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Protocol: realtime, openai-insecure-api-key.sk-ws\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if p := h.up.last.header.Get("Sec-WebSocket-Protocol"); p != "realtime, openai-insecure-api-key.sk-ws" {
		t.Errorf("subprotocol changed: %q", p)
	}
	io.WriteString(conn, "frame-one")
	buf := make([]byte, 9)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "FRAME-ONE" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	if !strings.Contains(h.logText(), `"http_status":101`) {
		t.Errorf("upgrade not logged: %s", h.logText())
	}
}

func TestBodyLimit(t *testing.T) {
	h := newHarness(t, 1<<20)
	// declared too large: rejected before New API is contacted
	resp, err := http.Post(h.guard.URL+"/v1/chat/completions", "application/json", bytes.NewReader(make([]byte, 1<<20+1)))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 413 || !strings.Contains(string(b), "BODY_TOO_LARGE") || h.up.hits.Load() != 0 {
		t.Errorf("declared: %d %s hits=%d", resp.StatusCode, b, h.up.hits.Load())
	}
	// chunked (no Content-Length) and too large: cut off while streaming
	pr, pw := io.Pipe()
	go func() { pw.Write(make([]byte, 2<<20)); pw.Close() }()
	req, _ := http.NewRequest("POST", h.guard.URL+"/v1/chat/completions", pr)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Errorf("chunked oversize: %d", resp.StatusCode)
	}
}

func TestUpstreamDown(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1") // nothing listens
	g := httptest.NewServer(New(u, Options{Mode: "disabled", MaxBody: 1 << 20, Audit: audit.New(io.Discard, bytes.Repeat([]byte("k"), 32))}))
	defer g.Close()
	resp, err := http.Post(g.URL+"/v1/chat/completions", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Error struct{ Type, Code, Message string }
	}
	json.NewDecoder(resp.Body).Decode(&e)
	resp.Body.Close()
	if resp.StatusCode != 502 || e.Error.Type != "new_api_error" || e.Error.Code != "UPSTREAM_UNAVAILABLE" ||
		!strings.Contains(e.Error.Message, "request id: rg-") {
		t.Errorf("got %d %+v", resp.StatusCode, e)
	}
}
