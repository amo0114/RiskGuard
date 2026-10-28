package console

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"riskguard/internal/audit"
	"riskguard/internal/policy"
	"riskguard/internal/samples"
)

var token = strings.Repeat("t", 40)

func newTestConsole(t *testing.T) (*httptest.Server, *Stats) {
	t.Helper()
	st, err := NewStats(filepath.Join(t.TempDir(), "stats.json"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, []byte(token), time.Hour, Info{Mode: "shadow", PolicyVersion: "p1", Model: "m", StartedAt: time.Now(),
		AuditFailures: func() int { return 0 }}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, st
}

func post(t *testing.T, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func get(t *testing.T, url string, ck *http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAuth(t *testing.T) {
	srv, _ := newTestConsole(t)
	if res := get(t, srv.URL+"/console/api/summary", nil); res.StatusCode != 401 {
		t.Fatalf("no session: %d", res.StatusCode)
	}
	if res := get(t, srv.URL+"/console/api/summary", &http.Cookie{Name: cookieName, Value: "forged"}); res.StatusCode != 401 {
		t.Fatalf("forged session: %d", res.StatusCode)
	}
	if res := post(t, srv.URL+"/console/api/login", `{"token":"wrong"}`, nil); res.StatusCode != 401 {
		t.Fatalf("bad token: %d", res.StatusCode)
	}
	if res := post(t, srv.URL+"/console/api/login", `{"token":"`+token+`"}`, map[string]string{"Origin": "https://evil.example"}); res.StatusCode != 403 {
		t.Fatalf("cross-origin login: %d", res.StatusCode)
	}
	res := post(t, srv.URL+"/console/api/login", `{"token":"`+token+`"}`, map[string]string{"Origin": srv.URL})
	if res.StatusCode != 200 || len(res.Cookies()) != 1 {
		t.Fatalf("login: %d %v", res.StatusCode, res.Cookies())
	}
	ck := res.Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/console/" {
		t.Fatalf("cookie attributes: %+v", ck)
	}
	for _, p := range []string{"/console/api/summary?range=1h", "/console/api/summary?range=7d", "/console/api/events", "/console/api/config"} {
		if r := get(t, srv.URL+p, ck); r.StatusCode != 200 {
			t.Fatalf("%s: %d", p, r.StatusCode)
		}
	}
	if r := post(t, srv.URL+"/console/api/logout", "", map[string]string{"Cookie": ck.Name + "=" + ck.Value}); r.StatusCode != 200 {
		t.Fatalf("logout: %d", r.StatusCode)
	}
	if r := get(t, srv.URL+"/console/api/summary", ck); r.StatusCode != 401 {
		t.Fatalf("session survived logout: %d", r.StatusCode)
	}
}

func TestLoginRateLimited(t *testing.T) {
	srv, _ := newTestConsole(t)
	last := 0
	for i := 0; i < 12; i++ {
		last = post(t, srv.URL+"/console/api/login", `{"token":"wrong"}`, nil).StatusCode
	}
	if last != 429 {
		t.Fatalf("expected 429 after repeated failures, got %d", last)
	}
}

func TestStaticHeaders(t *testing.T) {
	srv, _ := newTestConsole(t)
	index := get(t, srv.URL+"/console/", nil)
	body, _ := io.ReadAll(index.Body)
	index.Body.Close()
	m := regexp.MustCompile(`<meta name="csp-nonce" content="([A-Z2-7]+)"`).FindSubmatch(body)
	if index.StatusCode != 200 || m == nil {
		t.Fatalf("index: %d, nonce not stamped", index.StatusCode)
	}
	if csp := index.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "style-src 'self' 'nonce-"+string(m[1])+"'") {
		t.Fatalf("index CSP does not carry the page nonce: %s", csp)
	}
	again := get(t, srv.URL+"/console/", nil)
	again.Body.Close()
	if strings.Contains(again.Header.Get("Content-Security-Policy"), string(m[1])) {
		t.Fatal("nonce reused across responses")
	}

	asset := regexp.MustCompile(`/console/assets/[^"]+\.js`).Find(body)
	if asset == nil {
		t.Fatal("index references no script")
	}
	for _, p := range []string{"/console/", string(asset), "/console/favicon.svg"} {
		res := get(t, srv.URL+p, nil)
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
		csp := res.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe-inline") ||
			!strings.Contains(csp, "frame-ancestors 'none'") || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: security headers missing: %v", p, res.Header)
		}
		wantCache := "no-store"
		if strings.HasPrefix(p, "/console/assets/") {
			wantCache = "public, max-age=31536000, immutable"
		}
		if cc := res.Header.Get("Cache-Control"); cc != wantCache {
			t.Fatalf("%s: Cache-Control %q, want %q", p, cc, wantCache)
		}
	}
}

func TestStatsAggregationAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	st, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st.Add(audit.Event{Timestamp: now, Decision: "passthrough", HTTPStatus: 200})
	st.Add(audit.Event{Timestamp: now, TraceID: "rg-1", Decision: "allow", Protocol: "openai", ClassifierStatus: "ok", Label: "Safe", ClassifierMS: 1200, HTTPStatus: 200})
	st.Add(audit.Event{Timestamp: now, TraceID: "rg-2", Decision: "review", ReasonCode: "UNSAFE_CATEGORY", Protocol: "openai", ClassifierStatus: "ok",
		Label: "Unsafe", Categories: []string{"Violent"}, ClassifierMS: 4000, WouldBlock: true, HTTPStatus: 200})
	st.Add(audit.Event{Timestamp: now, TraceID: "rg-3", Decision: "allow", ClassifierStatus: "ok", Label: "Safe", CacheHit: true, HTTPStatus: 200})
	st.Add(audit.Event{Timestamp: now, TraceID: "rg-4", Decision: "unavailable", ReasonCode: "CLASSIFIER_BUSY", ClassifierStatus: "busy", Label: "Unknown", HTTPStatus: 200})

	check := func(st *Stats) {
		t.Helper()
		sm := st.Summary(time.Hour, time.Minute)
		tt := sm.Totals
		if tt.Requests != 5 || tt.Guarded != 4 || tt.NewTurns != 2 || tt.CacheHits != 1 || tt.WouldBlock != 1 || tt.ClsErrors != 1 {
			t.Fatalf("totals: %+v", tt)
		}
		if tt.Decisions["allow"] != 2 || tt.Labels["Unsafe"] != 1 || tt.Categories["Violent"] != 1 || sm.PeakTurns != 2 {
			t.Fatalf("breakdown: %+v peak=%d", tt, sm.PeakTurns)
		}
		if sm.LatencyP50 != 1500 || sm.LatencyP99 != 5000 || len(sm.Series) != 60 {
			t.Fatalf("latency/series: p50=%d p99=%d n=%d", sm.LatencyP50, sm.LatencyP99, len(sm.Series))
		}
		if ev := st.Events(); len(ev) != 4 || ev[0].TraceID != "rg-4" {
			t.Fatalf("events: %+v", ev)
		}
	}
	check(st)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	reloaded, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	check(reloaded)

	os.WriteFile(path, []byte("{broken"), 0o600)
	if _, err := NewStats(path); err == nil {
		t.Fatal("corrupt state file must be an error, not a silent reset")
	}
}

func TestEventRingKeepsNewest(t *testing.T) {
	st, _ := NewStats(filepath.Join(t.TempDir(), "s.json"))
	for i := 0; i < recentEvents+20; i++ {
		st.Add(audit.Event{Timestamp: time.Now(), TraceID: fmt.Sprint("rg-", i), Decision: "allow"})
	}
	ev := st.Events()
	if len(ev) != recentEvents || ev[0].TraceID != fmt.Sprint("rg-", recentEvents+19) || ev[len(ev)-1].TraceID != "rg-20" {
		t.Fatalf("ring: n=%d first=%s last=%s", len(ev), ev[0].TraceID, ev[len(ev)-1].TraceID)
	}
}

func TestBlockReplySwitch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	st, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	var on atomic.Bool
	pol := &policy.Policy{Version: "p1"}
	mux := http.NewServeMux()
	New(st, []byte(token), time.Hour, Info{Mode: "enforce", StartedAt: time.Now(), AuditFailures: func() int { return 0 },
		Policy: pol, BlockReply: &on}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ck := post(t, srv.URL+"/console/api/login", `{"token":"`+token+`"}`, map[string]string{"Origin": srv.URL}).Cookies()[0]
	set := func(body string, hdr map[string]string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/console/api/block-reply", strings.NewReader(body))
		req.AddCookie(ck)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	same := map[string]string{"Origin": srv.URL}

	if code := set(`{"enabled":true}`, same); code != 409 || on.Load() {
		t.Fatalf("no replies configured: %d %v", code, on.Load())
	}
	pol.Enforce.BlockReplies = []string{"a"}
	if code := set(`{"enabled":true}`, map[string]string{"Origin": "https://evil.example"}); code != 403 || on.Load() {
		t.Fatalf("cross-origin: %d", code)
	}
	if code := set(`{}`, same); code != 400 {
		t.Fatalf("missing enabled: %d", code)
	}
	if code := set(`{"enabled":true}`, same); code != 200 || !on.Load() {
		t.Fatalf("enable: %d %v", code, on.Load())
	}
	res := get(t, srv.URL+"/console/api/config", ck)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), `"block_reply":{"available":true,"count":1,"enabled":true}`) {
		t.Fatalf("config: %s", body)
	}
	if reloaded, err := NewStats(path); err != nil || !reloaded.BlockReply() {
		t.Fatalf("switch not persisted: %v", err)
	}
	if code := set(`{"enabled":false}`, same); code != 200 || on.Load() {
		t.Fatalf("disable: %d", code)
	}
	if reloaded, _ := NewStats(path); reloaded.BlockReply() {
		t.Fatal("disable not persisted")
	}
}

func TestAccountsFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.yaml")
	tok1, e1, err := NewAccount("alice", []string{RoleReviewer})
	if err != nil {
		t.Fatal(err)
	}
	_, e2, _ := NewAccount("bob", []string{RoleAdmin})
	os.WriteFile(path, []byte("accounts:\n"+indent(e1)+indent(e2)), 0o600)
	accs, err := LoadAccounts(path)
	if err != nil || len(accs) != 2 || accs[0].Name != "alice" || strings.Contains(e1, tok1) {
		t.Fatalf("load: %v %+v (entry must hold only the digest)", err, accs)
	}
	for _, bad := range [][]string{{"root"}, {RoleReviewer, "superuser"}} {
		if _, _, err := NewAccount("x", bad); err == nil {
			t.Errorf("roles %v accepted", bad)
		}
	}
	if _, _, err := NewAccount(sharedActor, nil); err == nil {
		t.Error("reserved name accepted")
	}
	os.WriteFile(path, []byte("accounts:\n"+indent(e1)+indent(e1)), 0o600)
	if _, err := LoadAccounts(path); err == nil {
		t.Error("duplicate account accepted")
	}
}

func indent(entry string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(entry, "\n"), "\n") {
		b.WriteString("  " + l + "\n")
	}
	return b.String()
}

func TestSampleRolesAndAccessAudit(t *testing.T) {
	dir := t.TempDir()
	cfg := samples.Config{Enabled: true, Path: filepath.Join(dir, "s.db"), EncryptionKeyFile: "e", DedupKeyFile: "d",
		MaxTextBytes: 4096, BaseProbability: 1, BaseDailyCap: 10, EnrichedDailyCap: 10, QueueItems: 4, QueueBytes: 1 << 20,
		QueueMaxAge: 5 * time.Second, ContentRetention: time.Hour, ReviewRetention: time.Hour, AuditRetention: time.Hour, MaxDBBytes: 1 << 30}
	st, err := samples.Open(cfg, []byte(strings.Repeat("e", 32)), []byte(strings.Repeat("d", 32)))
	if err != nil {
		t.Fatal(err)
	}
	col := samples.NewCollector(cfg, st)
	col.Offer(col.Candidate("token sk-SYNTHETICabcdefghijklmnop leaked?", false),
		audit.Event{TraceID: "rg-1", Timestamp: time.Now(), Decision: "review", Phase: "enforce"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t.Cleanup(func() { col.Close(ctx) })
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if l, _ := st.List(samples.Filter{}); len(l) == 1 {
			break
		}
	}

	aliceTok, aliceEntry, _ := NewAccount("alice", []string{RoleReviewer})
	bobTok, bobEntry, _ := NewAccount("bob", []string{RoleAdmin})
	accPath := filepath.Join(dir, "accounts.yaml")
	os.WriteFile(accPath, []byte("accounts:\n"+indent(aliceEntry)+indent(bobEntry)), 0o600)
	accs, err := LoadAccounts(accPath)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(nil, []byte(token), time.Hour, Info{Mode: "enforce", PolicyVersion: "p1", StartedAt: time.Now(),
		AuditFailures: func() int { return 0 }, Accounts: accs, Samples: col}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	same := map[string]string{"Origin": srv.URL}
	login := func(tok string) *http.Cookie {
		res := post(t, srv.URL+"/console/api/login", `{"token":"`+tok+`"}`, same)
		if res.StatusCode != 200 {
			t.Fatalf("login: %d", res.StatusCode)
		}
		return res.Cookies()[0]
	}
	call := func(ck *http.Cookie, method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.AddCookie(ck)
		req.Header.Set("Origin", srv.URL)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, string(b)
	}
	list, _ := st.List(samples.Filter{})
	id := fmt.Sprint(list[0].ID)

	shared, alice, bob := login(token), login(aliceTok), login(bobTok)
	if code, body := call(shared, "GET", "/console/api/samples", ""); code != 200 || !strings.Contains(body, `"trace_id":"rg-1"`) || strings.Contains(body, "leaked") {
		t.Errorf("shared list: %d %s", code, body)
	}
	for _, c := range []struct {
		ck           *http.Cookie
		method, path string
		want         int
	}{
		{shared, "GET", "/console/api/samples/" + id, 403},
		{shared, "POST", "/console/api/samples/" + id + "/reviews", 403},
		{bob, "GET", "/console/api/samples/" + id, 403}, // admin does not imply reviewer
		{alice, "POST", "/console/api/samples/" + id + "/delete", 403},
	} {
		if code, _ := call(c.ck, c.method, c.path, `{"status":"disputed"}`); code != c.want {
			t.Errorf("%s %s: %d want %d", c.method, c.path, code, c.want)
		}
	}
	code, body := call(alice, "GET", "/console/api/samples/"+id, "")
	if code != 200 || !strings.Contains(body, "[REDACTED_API_KEY] leaked?") || strings.Contains(body, "SYNTHETIC") {
		t.Errorf("alice detail: %d %s", code, body)
	}
	if code, _ := call(alice, "POST", "/console/api/samples/"+id+"/reviews", `{"status":"labeled","expected_action":"allow"}`); code != 200 {
		t.Errorf("review: %d", code)
	}
	if code, _ := call(alice, "POST", "/console/api/samples/"+id+"/reviews", `{"status":"disputed"}`); code != 409 {
		t.Errorf("stale review: %d", code)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/console/api/samples/"+id+"/reviews", strings.NewReader(`{"status":"disputed","supersedes":1}`))
	req.AddCookie(alice)
	req.Header.Set("Origin", "https://evil.example")
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 403 {
		t.Errorf("cross-origin review: %d", res.StatusCode)
	}
	if code, _ := call(bob, "POST", "/console/api/samples/"+id+"/delete", ""); code != 200 {
		t.Errorf("admin delete: %d", code)
	}
	if code, body := call(alice, "GET", "/console/api/config", ""); code != 200 || !strings.Contains(body, `"me":{"actor":"alice","roles":["reviewer"]}`) {
		t.Errorf("config me: %s", body)
	}

	db, _ := sql.Open("sqlite", cfg.Path)
	defer db.Close()
	rows, _ := db.Query(`SELECT actor || ':' || action || ':' || result FROM access_audit ORDER BY id`)
	var got []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		got = append(got, s)
	}
	rows.Close()
	want := "shared-token:login:ok alice:login:ok bob:login:ok alice:view_content:ok alice:review:ok alice:review:conflict bob:delete:ok"
	if strings.Join(got, " ") != want {
		t.Errorf("access audit:\n got %v\nwant %s", got, want)
	}
}
