package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDrainClosesWebSocketAndWritesAudit(t *testing.T) {
	h := newHarness(t, 1<<20)
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.guard.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: synthetic\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	handler := h.guard.Config.Handler.(*Handler)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.Drain(ctx); err != context.Canceled {
		t.Fatalf("drain should exhaust its budget: %v", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := handler.Drain(cleanup); err != nil {
		t.Fatal(err)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("WebSocket remained open")
	}
	if ev := lastEvent(t, h); ev.HTTPStatus != 101 || ev.ReasonCode != "SHUTDOWN_CANCELLED" {
		t.Fatalf("missing upgrade cancellation audit: %+v", ev)
	}
	handler.auditMu.Lock()
	defer handler.auditMu.Unlock()
	if len(handler.hijacked) != 0 {
		t.Fatal("hijacked connection tracking leaked")
	}
}

func TestDrainCancelsShadowAndWritesAudit(t *testing.T) {
	c := safeClassifier()
	c.delay = 30 * time.Second
	g := testGuard(t, c)
	g.ClassifierTimeout = time.Minute
	h := newHarnessMode(t, "shadow", 1<<20, g)
	post(t, h.guard.URL+"/v1/chat/completions", chatBody("synthetic safe text"))
	handler := h.guard.Config.Handler.(*Handler)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.Drain(ctx); err != context.Canceled {
		t.Fatalf("drain should exhaust its budget: %v", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := handler.Drain(cleanup); err != nil {
		t.Fatal(err)
	}
	logs := h.logText()
	if strings.Count(logs, "\n") != 1 || !strings.Contains(logs, "SHUTDOWN_CANCELLED") {
		t.Fatalf("missing cancellation audit: %s", logs)
	}
	resp, _ := post(t, h.guard.URL+"/v1/chat/completions", chatBody("arriving after drain"))
	if resp.StatusCode != http.StatusServiceUnavailable || strings.Count(h.logText(), "\n") != 1 {
		t.Fatal("draining handler accepted a new request")
	}
}
