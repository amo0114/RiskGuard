package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type doctorEnv struct {
	dir, cfg, spool string
	clsCalls        atomic.Int32
	cls, admin, up  *httptest.Server
}

// newDoctorEnv writes a shadow config whose admin listener is a fake running instance, with a
// mock classifier and New API. readyMode is what the fake instance reports.
func newDoctorEnv(t *testing.T, readyMode, label string) *doctorEnv {
	return newDoctorEnvReady(t, `{"status":"ready","mode":"`+readyMode+`"}`, label)
}

func newDoctorEnvReady(t *testing.T, readyBody, label string) *doctorEnv {
	t.Helper()
	e := &doctorEnv{dir: t.TempDir()}
	e.cls = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.clsCalls.Add(1)
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"model":"mock-guard","choices":[{"message":{"content":"Safety: `+label+`\nCategories: None"},"finish_reason":"stop"}]}`)
	}))
	e.admin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__risk/readyz":
			io.WriteString(w, readyBody)
		case "/__risk/classifier":
			io.WriteString(w, `{"last_ok":"2026-10-28T10:00:00Z","last_failure":"0001-01-01T00:00:00Z"}`)
		}
	}))
	e.up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(func() { e.cls.Close(); e.admin.Close(); e.up.Close() })
	write := func(name, body string) string {
		p := filepath.Join(e.dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	e.spool = filepath.Join(e.dir, "spool")
	os.Mkdir(e.spool, 0o700)
	policy, _ := filepath.Abs("../../config/policy-v1.yaml")
	template, err := os.ReadFile("../../config/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = write("config.yaml", strings.NewReplacer(
		"127.0.0.1:4101", strings.TrimPrefix(e.admin.URL, "http://"),
		// The internal and public example configs name different classifier endpoints.
		"http://127.0.0.1:4000", e.up.URL, "http://10.88.0.2:8088", e.cls.URL, "http://127.0.0.1:8088", e.cls.URL,
		"/etc/riskguard/hmac.key", write("hmac.key", strings.Repeat("h", 48)),
		"/etc/riskguard/guard.key", write("guard.key", "synthetic-key"),
		"/etc/riskguard/console.token", write("console.token", strings.Repeat("t", 40)),
		"/etc/riskguard/policy-v1.yaml", policy,
		"/var/lib/riskguard/console-stats.json", filepath.Join(e.dir, "state.json"),
		"/var/lib/riskguard/spool", e.spool,
	).Replace(string(template)))
	return e
}

func runDoc(t *testing.T, e *doctorEnv, probe bool, urls ...string) (string, int) {
	t.Helper()
	var b bytes.Buffer
	code := runDoctor(&b, e.cfg, probe, urls)
	return b.String(), code
}

func line(out, check string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, " "+check+" ") {
			return l
		}
	}
	return ""
}

func TestDoctorDefaultIsReadOnlyAndSendsNothing(t *testing.T) {
	e := newDoctorEnv(t, "shadow", "Safe")
	// A live request's spool file: unlike -check, doctor must not clean the running instance's spool.
	live := filepath.Join(e.spool, "rg-spool-live")
	os.WriteFile(live, []byte("in flight"), 0o600)
	before, _ := os.ReadDir(e.dir)
	out, code := runDoc(t, e, false, "http://127.0.0.1:1/never")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if e.clsCalls.Load() != 0 {
		t.Error("default run called the classifier")
	}
	if _, err := os.Stat(live); err != nil {
		t.Error("doctor removed a spool file")
	}
	if after, _ := os.ReadDir(e.dir); len(after) != len(before) {
		t.Errorf("files changed: %d -> %d", len(before), len(after))
	}
	for check, status := range map[string]string{
		"config": docPass, "policy": docWarn, "policy exemptions": docWarn, "secret files": docPass,
		"state directories": docPass, "running instance": docPass, "classifier health": docPass, "upstream": docPass,
		"classifier probe": docNotVerified, "entry probes": docNotVerified, "entry completeness": docNotVerified,
	} {
		if l := line(out, check); !strings.HasPrefix(l, status) {
			t.Errorf("%s: want %s, got %q", check, status, l)
		}
	}
	if strings.Contains(out, "synthetic-key") || strings.Contains(out, strings.Repeat("t", 40)) {
		t.Error("secret printed")
	}
}

func TestDoctorFailures(t *testing.T) {
	e := newDoctorEnv(t, "enforce", "Safe")
	os.Chmod(filepath.Join(e.dir, "guard.key"), 0o644)
	os.Remove(e.spool)
	out, code := runDoc(t, e, false)
	if l := line(out, "state directories"); !strings.HasPrefix(l, docWarn) || !strings.Contains(l, "not created yet") {
		t.Errorf("missing spool dir: %q", l)
	}
	if code != 1 || !strings.HasPrefix(line(out, "secret files"), docFail) {
		t.Errorf("world-readable key: exit %d\n%s", code, out)
	}
	// The instance runs in another mode than the file says: a pending restart, a warning.
	if l := line(out, "running instance"); !strings.HasPrefix(l, docWarn) || !strings.Contains(l, "restart") {
		t.Errorf("mode drift: %q", l)
	}

	bad := newDoctorEnv(t, "shadow", "Safe")
	os.WriteFile(bad.cfg, []byte("mode: audit\n"), 0o600)
	if out, code := runDoc(t, bad, true); code != 1 || !strings.HasPrefix(line(out, "config"), docFail) || bad.clsCalls.Load() != 0 {
		t.Errorf("broken config: exit %d\n%s", code, out)
	}
}

func TestDoctorProbes(t *testing.T) {
	e := newDoctorEnv(t, "shadow", "Safe")
	guarded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Risk-Trace-Id", "rg-x")
	}))
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer guarded.Close()
	defer direct.Close()
	out, code := runDoc(t, e, true, guarded.URL+"/api/status")
	if code != 0 || e.clsCalls.Load() != 1 || !strings.HasPrefix(line(out, "classifier probe"), docPass) ||
		!strings.HasPrefix(line(out, "entry probe"), docPass) {
		t.Errorf("probes: exit %d calls %d\n%s", code, e.clsCalls.Load(), out)
	}
	// Completeness stays unverified even when every listed entry passes.
	if !strings.HasPrefix(line(out, "entry completeness"), docNotVerified) {
		t.Error("entry completeness claimed")
	}
	if out, code := runDoc(t, e, true, direct.URL+"/api/status"); code != 1 || !strings.HasPrefix(line(out, "entry probe"), docFail) {
		t.Errorf("bypassing entry: exit %d\n%s", code, out)
	}

	// Credentials or tokens in the URL: never sent (Go would turn user info into Basic auth) and
	// never printed.
	var seen atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen.Add(1) }))
	defer trap.Close()
	host := strings.TrimPrefix(trap.URL, "http://")
	for _, u := range []string{"http://alice:s3cret@" + host + "/api/status", trap.URL + "/api/status?key=s3cret",
		trap.URL + "/x#s3cret", "ftp://" + host + "/", "http:///api/status"} {
		out, code := runDoc(t, e, true, u)
		if code != 1 || !strings.HasPrefix(line(out, "entry probe"), docFail) || strings.Contains(out, "s3cret") {
			t.Errorf("%s: exit %d\n%s", u, code, out)
		}
	}
	if seen.Load() != 0 {
		t.Errorf("rejected entry URLs were requested %d times", seen.Load())
	}

	unsafe := newDoctorEnv(t, "shadow", "Unsafe")
	if out, _ := runDoc(t, unsafe, true); !strings.HasPrefix(line(out, "classifier probe"), docWarn) {
		t.Errorf("benign probe labelled unsafe:\n%s", out)
	}
}

func TestDoctorReadinessNeedsReadyStatus(t *testing.T) {
	for _, body := range []string{`{"status":"starting","mode":"shadow"}`, `{"mode":"shadow"}`} {
		e := newDoctorEnvReady(t, body, "Safe")
		out, _ := runDoc(t, e, false)
		if l := line(out, "running instance"); !strings.HasPrefix(l, docWarn) {
			t.Errorf("%s: %q", body, l)
		}
	}
}

func TestDoctorDisabledModePolicyNotUsed(t *testing.T) {
	e := newDoctorEnv(t, "disabled", "Safe")
	raw, _ := os.ReadFile(e.cfg)
	cfg := strings.Replace(string(raw), `mode: "shadow"`, `mode: "disabled"`, 1)
	os.WriteFile(e.cfg, []byte(cfg), 0o600)
	out, code := runDoc(t, e, true)
	if code != 0 || !strings.HasPrefix(line(out, "policy"), docNotVerified) || e.clsCalls.Load() != 0 {
		t.Errorf("disabled: exit %d calls %d\n%s", code, e.clsCalls.Load(), out)
	}
	// A policy that would not load is a warning while disabled (-check accepts it), not a failure.
	os.WriteFile(e.cfg, []byte(strings.Replace(cfg, "policy-v1.yaml", "missing.yaml", 1)), 0o600)
	if out, code := runDoc(t, e, false); code != 0 || !strings.HasPrefix(line(out, "policy"), docWarn) {
		t.Errorf("disabled with missing policy: exit %d\n%s", code, out)
	}
}
