// Package proxy is the hop between OpenResty and New API. Every forwarded request reaches New API
// unchanged (method, path encoding, query, headers, body bytes, streamed response). In shadow and
// enforce modes model-submission requests are first buffered, inspected and classified; only
// enforce mode may answer instead of New API. Identity is never decided here: New API stays the
// auth authority.
package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"riskguard/internal/audit"
	"riskguard/internal/routes"
	"riskguard/internal/samples"
)

const TraceHeader = "X-Risk-Trace-Id"

type Options struct {
	Mode    string // disabled | shadow | enforce
	MaxBody int64
	Audit   *audit.Logger
	Guard   *Guard // required unless Mode is disabled
	// Samples, when set, is offered the inspected text and final event of guarded requests.
	Samples *samples.Collector
}

type Handler struct {
	mode    string
	maxBody int64
	audit   *audit.Logger
	guard   *Guard
	samples *samples.Collector
	rp      *httputil.ReverseProxy

	shadowCtx    context.Context
	cancelShadow context.CancelFunc
	auditMu      sync.Mutex
	auditPending int
	draining     bool
	auditDone    chan struct{}
	hijacked     map[*trackedConn]struct{}
}

func New(upstream *url.URL, o Options) *Handler {
	h := &Handler{mode: o.Mode, maxBody: o.MaxBody, audit: o.Audit, guard: o.Guard, samples: o.Samples}
	h.shadowCtx, h.cancelShadow = context.WithCancel(context.Background())
	h.auditDone = make(chan struct{})
	h.hijacked = make(map[*trackedConn]struct{})
	if h.mode == "disabled" {
		h.guard = nil
	}
	h.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			// OpenResty sets Host to the public site name; New API sees exactly what it sees today.
			pr.Out.Host = pr.In.Host
			// ReverseProxy drops inbound X-Forwarded-* before Rewrite. The only peer on this loopback
			// listener is OpenResty, which already built the chain; restore it verbatim instead of
			// appending 127.0.0.1, which would become New API's ClientIP.
			for _, k := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v, ok := pr.In.Header[k]; ok {
					pr.Out.Header[k] = v
				}
			}
		},
		Transport:    newTransport(),
		ErrorHandler: h.upstreamError,
		// A 101 response is written straight onto the hijacked connection, bypassing WriteHeader,
		// so record it here for the audit line.
		ModifyResponse: func(res *http.Response) error {
			if rec, ok := res.Request.Context().Value(recorderKey{}).(*recorder); ok && res.StatusCode == http.StatusSwitchingProtocols {
				rec.status = res.StatusCode
			}
			return nil
		},
		// Default FlushInterval: ReverseProxy already flushes text/event-stream and unknown-length
		// bodies immediately, which covers SSE without per-write flushes on large JSON bodies.
	}
	return h
}

func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // never honour HTTP(S)_PROXY from the service environment
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true, // keep Accept-Encoding/Content-Encoding exactly as the client sent
		ExpectContinueTimeout: time.Second,
		// No ResponseHeaderTimeout: slow first tokens are legitimate; client cancellation ends the call.
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	trace := newTraceID()
	rt := routes.Classify(r)
	if !h.beginAudit() {
		w.Header().Set(TraceHeader, trace)
		writeError(w, rt.Protocol, http.StatusServiceUnavailable, "GUARD_UNAVAILABLE", "content guard shutting down", trace)
		return
	}
	rec := &recorder{ResponseWriter: w, trackHijacked: h.trackHijacked}
	ev := &audit.Event{
		TraceID:      trace,
		Phase:        h.mode,
		RouteClass:   string(rt.Class),
		Protocol:     rt.Protocol,
		Method:       r.Method,
		PathTemplate: rt.Template,
		SourceIPHMAC: h.audit.Fingerprint(r.Header.Get("X-Real-IP")),
		Client:       clientOf(r.UserAgent()),
		Decision:     "passthrough",
	}
	if c := credential(r); c != "" {
		ev.CredentialHMAC = h.audit.Fingerprint("cred:" + c)
	}
	if h.guard != nil {
		ev.PolicyVersion = h.guard.Policy.Version
	}
	// pending is set by shadow classification still running after the response was forwarded;
	// the handler must return (so the response flushes and the connection is reused) and the
	// audit line is written once the classification completes.
	var pending <-chan struct{}
	var cand *samples.Candidate // set once the inspected text is known
	defer func() {
		ev.Timestamp = start.UTC()
		ev.HTTPStatus = rec.status
		ev.LatencyMS = time.Since(start).Milliseconds()
		ev.ClientAborted = r.Context().Err() != nil
		if rec.hijacked != nil && rec.hijacked.forced.Load() {
			ev.ReasonCode = "SHUTDOWN_CANCELLED"
		}
		if pending == nil {
			defer h.endAudit()
			h.audit.Log(*ev)
			h.samples.Offer(cand, *ev)
			return
		}
		go func() {
			defer h.endAudit()
			<-pending
			h.audit.Log(*ev)
			h.samples.Offer(cand, *ev)
		}()
	}()

	w.Header().Set(TraceHeader, trace)
	r.Header.Set(TraceHeader, trace)
	if r.ContentLength > h.maxBody {
		ev.Decision, ev.ReasonCode = "reject", "BODY_TOO_LARGE"
		writeError(rec, rt.Protocol, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body too large", trace)
		return
	}
	if h.guard == nil || rt.Class == routes.AdminPassthrough || rt.Class == routes.ReadPassthrough {
		if rt.Class == routes.Unknown || rt.Class == routes.ModelUninspectable {
			ev.Coverage, ev.ReasonCode = "unsupported", "COVERAGE_GAP"
		}
		h.forward(rec, r, ev, nil)
		return
	}
	h.guarded(rec, r, rt, ev, &pending, &cand)
}

func (h *Handler) beginAudit() bool {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	if h.draining {
		return false
	}
	h.auditPending++
	return true
}

func (h *Handler) endAudit() {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	h.auditPending--
	if h.draining && h.auditPending == 0 {
		close(h.auditDone)
	}
}

// Drain waits for request audit writes, including shadow work after handlers have returned.
// Stop the HTTP server first. A deadline cancels shadow calls; Drain can then be called again
// with a short cleanup budget to wait for their cancellation events to be written.
func (h *Handler) Drain(ctx context.Context) error {
	h.auditMu.Lock()
	if !h.draining {
		h.draining = true
		if h.auditPending == 0 {
			close(h.auditDone)
		}
	}
	h.auditMu.Unlock()
	select {
	case <-h.auditDone:
		h.cancelShadow()
		return nil
	case <-ctx.Done():
		h.cancelShadow()
		h.closeHijacked()
		return ctx.Err()
	}
}

// Hijacked connections are no longer owned by http.Server.Shutdown/Close. Track their lifetime
// through Close so normal WebSocket traffic never accumulates stale connection entries.
type trackedConn struct {
	net.Conn
	h      *Handler
	forced atomic.Bool
}

// Preserve ReverseProxy's half-close behavior for TCP/TLS upgrade tunnels.
func (c *trackedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.h.auditMu.Lock()
	delete(c.h.hijacked, c)
	c.h.auditMu.Unlock()
	return err
}

func (h *Handler) trackHijacked(conn net.Conn) *trackedConn {
	c := &trackedConn{Conn: conn, h: h}
	h.auditMu.Lock()
	cancelled := h.shadowCtx.Err() != nil
	if !cancelled {
		h.hijacked[c] = struct{}{}
	}
	h.auditMu.Unlock()
	if cancelled {
		c.forced.Store(true)
		c.Close()
	}
	return c
}

func (h *Handler) closeHijacked() {
	h.auditMu.Lock()
	conns := make([]*trackedConn, 0, len(h.hijacked))
	for c := range h.hijacked {
		conns = append(conns, c)
	}
	h.auditMu.Unlock()
	for _, c := range conns {
		c.forced.Store(true)
		c.Close()
	}
}

// forward sends r to New API. body replaces the request body when it was buffered; otherwise the
// original body is streamed through, capped at maxBody.
func (h *Handler) forward(rec *recorder, r *http.Request, ev *audit.Event, body io.ReadCloser) {
	if body == nil && r.Body != nil && r.Body != http.NoBody {
		body = http.MaxBytesReader(rec, r.Body, h.maxBody)
	}
	if body != nil {
		cb := &countingBody{rc: body}
		r.Body = cb
		defer func() { ev.BodyBytes = cb.n }()
	}
	h.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), recorderKey{}, rec)))
}

func (h *Handler) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	trace := w.Header().Get(TraceHeader)
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		writeError(w, "", http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body too large", trace)
	case r.Context().Err() != nil:
		// Client went away; nothing can be delivered. Recorded as client_aborted.
		if rec, ok := w.(*recorder); ok && rec.status == 0 {
			rec.status = 499
		}
	default:
		// No retry against anything else: New API is the only upstream (no fail-open path).
		writeError(w, routes.Classify(r).Protocol, http.StatusBadGateway, "UPSTREAM_UNAVAILABLE", "upstream service unavailable", trace)
	}
}

func newTraceID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "rg-" + hex.EncodeToString(b[:])
}

// recorder captures the status for the audit line. Unwrap lets http.ResponseController (used by
// ReverseProxy for Flush and for Hijack on 101 upgrades) reach the real connection.
type recorderKey struct{}

type recorder struct {
	http.ResponseWriter
	status        int
	trackHijacked func(net.Conn) *trackedConn
	hijacked      *trackedConn
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err != nil || r.trackHijacked == nil {
		return conn, rw, err
	}
	r.hijacked = r.trackHijacked(conn)
	return r.hijacked, rw, nil
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

type countingBody struct {
	rc io.ReadCloser
	n  int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingBody) Close() error { return c.rc.Close() }
