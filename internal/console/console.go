// Package console serves the operations dashboard on the admin listener. It shows the same
// metadata the audit log carries (never prompts, keys or raw addresses) and cannot change mode or
// policy: those remain approved config changes. Its one switch only picks how an already-decided
// rejection is worded (configured block reply or 4xx error), never whether a request is blocked.
package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"riskguard/internal/limits"
	"riskguard/internal/policy"
	"riskguard/internal/samples"
)

// dist is the built web/ app (npm run build); it is committed so `go build` needs no Node toolchain.
//
//go:embed all:dist
var dist embed.FS

const cookieName = "rg_console"

type Info struct {
	Mode          string
	PolicyVersion string
	Model         string
	StartedAt     time.Time
	// Health returns live classifier/spool state; nil when the Guard is disabled.
	Health        func() map[string]any
	AuditFailures func() int
	Policy        *policy.Policy // nil when the Guard is disabled
	BlockReply    *atomic.Bool   // the Guard's live block-reply switch; nil when the Guard is disabled
	Accounts      []Account
	Samples       *samples.Collector // nil when sampling is off
	SamplesError  string             // why configured sampling is not running
	// Settings are non-secret runtime limits shown read-only (no paths, keys or endpoints).
	Settings map[string]any
}

type Console struct {
	stats      *Stats
	info       Info
	tokenSum   [32]byte
	sessionTTL time.Duration
	logins     *limits.KeyedRate

	mu       sync.Mutex
	sessions map[string]session // session id -> who and until when
	now      func() time.Time
}

func New(stats *Stats, token []byte, sessionTTL time.Duration, info Info) *Console {
	return &Console{
		stats: stats, info: info, tokenSum: sha256.Sum256(token), sessionTTL: sessionTTL,
		// Token is >=32 random bytes; this only keeps a stuck script from hammering the endpoint.
		logins:   limits.NewKeyedRate(10, 1000),
		sessions: map[string]session{}, now: time.Now,
	}
}

// Register mounts the console under /console/ on mux.
func (c *Console) Register(mux *http.ServeMux) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("console: web app not built: " + err.Error())
	}
	files := http.StripPrefix("/console/", http.FileServer(http.FS(sub)))
	mux.Handle("GET /console/{$}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveIndex(w, index) }))
	mux.Handle("GET /console/", secure(files))
	// Vite content-hashes everything under assets/, so it can be cached forever.
	mux.Handle("GET /console/assets/", secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		files.ServeHTTP(w, r)
	})))
	mux.Handle("GET /console", http.RedirectHandler("/console/", http.StatusFound))
	mux.Handle("POST /console/api/login", secure(http.HandlerFunc(c.login)))
	mux.Handle("POST /console/api/logout", secure(c.authed(c.logout)))
	mux.Handle("GET /console/api/summary", secure(c.authed(c.summary)))
	mux.Handle("GET /console/api/events", secure(c.authed(c.events)))
	mux.Handle("GET /console/api/dimensions", secure(c.authed(c.dimensions)))
	mux.Handle("POST /console/api/aliases", secure(c.authed(c.require(RoleAdmin, c.setAlias))))
	mux.Handle("GET /console/api/config", secure(c.authed(c.config)))
	mux.Handle("POST /console/api/block-reply", secure(c.authed(c.setBlockReply)))
	mux.Handle("GET /console/api/samples", secure(c.authed(c.sampleList)))
	mux.Handle("GET /console/api/samples/status", secure(c.authed(c.sampleStatus)))
	mux.Handle("GET /console/api/samples/{id}", secure(c.authed(c.require(RoleReviewer, c.sampleDetail))))
	mux.Handle("POST /console/api/samples/{id}/reviews", secure(c.authed(c.require(RoleReviewer, c.sampleReview))))
	mux.Handle("POST /console/api/samples/{id}/delete", secure(c.authed(c.require(RoleAdmin, c.sampleDelete))))
}

func setSecurityHeaders(h http.Header, styleSrc string) {
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src "+styleSrc+"; img-src 'self' data:; "+
		"connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header(), "'self'")
		h.ServeHTTP(w, r)
	})
}

// serveIndex stamps a fresh nonce into the page. Chart colours and the UI library's positioning
// styles are injected as <style> elements at runtime; the nonce allows exactly those instead of
// 'unsafe-inline'. Scripts stay 'self' only.
func serveIndex(w http.ResponseWriter, index []byte) {
	nonce := rand.Text()
	setSecurityHeaders(w.Header(), "'self' 'nonce-"+nonce+"'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(bytes.ReplaceAll(index, []byte("__CSP_NONCE__"), []byte(nonce)))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// sameOrigin rejects cross-site POSTs; SameSite=Strict already blocks the cookie, this also covers
// the login form.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	return strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://") == r.Host
}

func (c *Console) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request"})
		return
	}
	if !c.logins.Allow("login") {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(req.Token)))
	// The shared token only sees metadata; a named account brings its roles. Every digest is
	// compared so timing does not reveal which one matched.
	var sess session
	if subtle.ConstantTimeCompare(sum[:], c.tokenSum[:]) == 1 {
		sess.actor = sharedActor
	}
	for _, a := range c.info.Accounts {
		d, _ := hex.DecodeString(a.TokenSHA256)
		if subtle.ConstantTimeCompare(sum[:], d) == 1 {
			sess.actor, sess.roles = a.Name, a.Roles
		}
	}
	if sess.actor == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	var b [32]byte
	rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	exp := c.now().Add(c.sessionTTL)
	sess.exp = exp
	c.mu.Lock()
	for k, e := range c.sessions {
		if c.now().After(e.exp) {
			delete(c.sessions, k)
		}
	}
	c.sessions[id] = sess
	c.mu.Unlock()
	if st := c.store(); st != nil {
		if err := st.Audit(sess.actor, "login", "console", "ok"); err != nil {
			log.Printf("riskguard: console access audit: %v", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/console/", Expires: exp, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.Header.Get("X-Forwarded-Proto") == "https",
	})
	writeJSON(w, http.StatusOK, map[string]any{"expires": exp.UTC()})
}

func (c *Console) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request"})
			return
		}
		ck, err := r.Cookie(cookieName)
		var sess session
		ok := false
		if err == nil {
			c.mu.Lock()
			sess, ok = c.sessions[ck.Value]
			ok = ok && c.now().Before(sess.exp)
			c.mu.Unlock()
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(cookieName); err == nil {
		c.mu.Lock()
		delete(c.sessions, ck.Value)
		c.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/console/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{})
}

var ranges = map[string][2]time.Duration{
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, time.Hour},
}

func (c *Console) summary(w http.ResponseWriter, r *http.Request) {
	rg, ok := ranges[r.URL.Query().Get("range")]
	if !ok {
		rg = ranges["24h"]
	}
	var health map[string]any
	if c.info.Health != nil {
		health = c.info.Health()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": c.info.Mode, "policy_version": c.info.PolicyVersion, "model": c.info.Model,
		"started_at": c.info.StartedAt.UTC(), "health": health, "audit_failures": c.info.AuditFailures(),
		"stats": c.stats.Summary(rg[0], rg[1]),
	})
}

func (c *Console) events(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": c.stats.Events()})
}

// dimensions groups guarded events by key fingerprint, client or model. Aliases (people's names
// chosen by an admin) go only to named sessions with a role, not to the shared metadata token.
func (c *Console) dimensions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dim := q.Get("dim")
	if !slices.Contains(dims, dim) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dim must be credential, client or model"})
		return
	}
	rg, ok := ranges[q.Get("range")]
	if !ok {
		rg = ranges["24h"]
	}
	writeJSON(w, http.StatusOK, map[string]any{"dim": dim, "rows": c.stats.Dimension(dim, rg[0], len(sessionFrom(r).roles) > 0)})
}

func (c *Console) setAlias(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	actor := sessionFrom(r).actor
	if err := c.stats.SetAlias(req.Key, req.Name, actor); err != nil {
		if errors.Is(err, ErrBadAlias) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("riskguard: console alias save: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save alias"})
		return
	}
	log.Printf("riskguard: console alias %s set by %s", req.Key, actor)
	writeJSON(w, http.StatusOK, map[string]string{"key": req.Key, "name": strings.TrimSpace(req.Name)})
}

func (c *Console) config(w http.ResponseWriter, r *http.Request) {
	var pol map[string]any
	if p := c.info.Policy; p != nil {
		pol = map[string]any{
			"version": p.Version, "labels": p.Labels, "unsafe_categories": p.UnsafeCategories,
			"unsafe_default": p.UnsafeDefault, "t0_only_protocols": p.T0OnlyProtocols,
			"coverage_exceptions": p.CoverageExceptions, "enforce": map[string]string{
				"review": p.Enforce.Review, "no_inspectable_input": p.Enforce.NoInspectableInput, "unparseable": p.Enforce.Unparseable,
			},
		}
	}
	sess := sessionFrom(r)
	aliases := map[string]Alias{}
	if len(sess.roles) > 0 && c.stats != nil {
		aliases = c.stats.Aliases()
	}
	writeJSON(w, http.StatusOK, map[string]any{"aliases": aliases, "mode": c.info.Mode, "model": c.info.Model, "policy": pol, "settings": c.info.Settings,
		"block_reply": map[string]any{"available": c.blockRepliesConfigured(), "enabled": c.info.BlockReply != nil && c.info.BlockReply.Load(),
			"count": c.blockReplyCount()},
		"me":      map[string]any{"actor": sess.actor, "roles": append([]string{}, sess.roles...)},
		"samples": map[string]bool{"enabled": c.info.Samples != nil}})
}

func (c *Console) blockReplyCount() int {
	if c.info.Policy == nil {
		return 0
	}
	return len(c.info.Policy.Enforce.BlockReplies)
}

func (c *Console) blockRepliesConfigured() bool {
	return c.info.BlockReply != nil && c.blockReplyCount() > 0
}

// setBlockReply persists before switching, so a restart never silently flips the live setting.
func (c *Console) setBlockReply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if !c.blockRepliesConfigured() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no block replies configured in policy"})
		return
	}
	if err := c.stats.SetBlockReply(*req.Enabled); err != nil {
		log.Printf("riskguard: console block_reply save: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save setting"})
		return
	}
	c.info.BlockReply.Store(*req.Enabled)
	log.Printf("riskguard: console set block_reply=%t", *req.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": *req.Enabled})
}
