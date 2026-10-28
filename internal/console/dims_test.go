package console

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"riskguard/internal/audit"
)

func TestDimensionsAggregateCapAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	st, _ := NewStats(path)
	now := time.Now()
	add := func(cred, client, model, decision string, at time.Time) {
		st.Add(audit.Event{Timestamp: at, Decision: decision, CredentialHMAC: cred, Client: client, Model: model,
			ClassifierStatus: "ok", Label: "Safe", Categories: map[bool][]string{true: {"Violent"}}[decision == "review"]})
	}
	add("aaaaaaaaaaaaaaaa", "codex-tui/1", "gpt-5", "allow", now)
	add("aaaaaaaaaaaaaaaa", "codex-tui/1", "gpt-5", "review", now)
	add("bbbbbbbbbbbbbbbb", "", "claude-x", "allow", now)
	add("aaaaaaaaaaaaaaaa", "codex-tui/1", "gpt-5", "allow", now.Add(-3*time.Hour)) // outside 1h
	st.Add(audit.Event{Timestamp: now, Decision: "passthrough", CredentialHMAC: "cccccccccccccccc"})
	for i := 0; i < dimCap+5; i++ { // random keys spill into (other)
		add(fmt.Sprintf("%016x", i+1000), "x", "y", "allow", now.Add(-2*time.Hour))
	}

	rows := st.Dimension(DimCredential, time.Hour, false)
	if len(rows) != 2 || rows[0].Key != "aaaaaaaaaaaaaaaa" || rows[0].Requests != 2 || rows[0].Decisions["review"] != 1 ||
		len(rows[0].Categories) != 1 || rows[0].Categories[0].Key != "Violent" {
		t.Fatalf("1h credential rows %+v", rows)
	}
	if c := st.Dimension(DimClient, time.Hour, false); len(c) != 2 || c[1].Key != "(none)" {
		t.Errorf("client rows %+v", c)
	}
	day := st.Dimension(DimCredential, 24*time.Hour, false)
	var other int
	for _, r := range day {
		if r.Key == dimOther {
			other = r.Requests
		}
	}
	if len(day) > dimCap+3 || other != 5 {
		t.Errorf("cap: %d rows, other=%d", len(day), other)
	}

	if err := st.SetAlias("aaaaaaaaaaaaaaaa", "alice-codex", "bob"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"AAAA", "x"}, {"aaaaaaaaaaaaaaaa", strings.Repeat("n", 41)}, {"aaaaaaaaaaaaaaaa", "a\nb"}} {
		if st.SetAlias(bad[0], bad[1], "bob") == nil {
			t.Errorf("accepted alias %q", bad)
		}
	}
	if r := st.Dimension(DimCredential, time.Hour, false); r[0].Alias != "" {
		t.Error("alias shown without a role")
	}
	re, err := NewStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := re.Dimension(DimCredential, time.Hour, true); r[0].Alias != "alice-codex" || r[0].Requests != 2 {
		t.Errorf("after reload %+v", r[0])
	}
	if a := re.Aliases()["aaaaaaaaaaaaaaaa"]; a.By != "bob" {
		t.Errorf("alias meta %+v", a)
	}
	if err := re.SetAlias("aaaaaaaaaaaaaaaa", "", "bob"); err != nil || len(re.Aliases()) != 0 {
		t.Errorf("remove alias: %v", err)
	}
}

func TestAliasesNeedAdminAndHideFromSharedToken(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStats(filepath.Join(dir, "s.json"))
	st.Add(audit.Event{Timestamp: time.Now(), Decision: "allow", CredentialHMAC: "aaaaaaaaaaaaaaaa"})
	st.SetAlias("aaaaaaaaaaaaaaaa", "alice", "seed")
	revTok, revEntry, _ := NewAccount("rev", []string{RoleReviewer})
	admTok, admEntry, _ := NewAccount("adm", []string{RoleAdmin})
	acc := filepath.Join(dir, "a.yaml")
	os.WriteFile(acc, []byte("accounts:\n"+indent(revEntry)+indent(admEntry)), 0o600)
	accs, err := LoadAccounts(acc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(st, []byte(token), time.Hour, Info{Mode: "shadow", StartedAt: time.Now(), AuditFailures: func() int { return 0 },
		Accounts: accs}).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	same := map[string]string{"Origin": srv.URL}
	login := func(tok string) *http.Cookie {
		return post(t, srv.URL+"/console/api/login", `{"token":"`+tok+`"}`, same).Cookies()[0]
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
	shared, rev, adm := login(token), login(revTok), login(admTok)
	for _, ck := range []*http.Cookie{shared} {
		_, dims := call(ck, "GET", "/console/api/dimensions?dim=credential&range=1h", "")
		_, cfg := call(ck, "GET", "/console/api/config", "")
		if strings.Contains(dims, "alice") || strings.Contains(cfg, "alice") || !strings.Contains(dims, "aaaaaaaaaaaaaaaa") {
			t.Errorf("shared token: %s / %s", dims, cfg)
		}
	}
	if _, dims := call(rev, "GET", "/console/api/dimensions?dim=credential", ""); !strings.Contains(dims, `"alias":"alice"`) {
		t.Errorf("reviewer dims %s", dims)
	}
	if code, _ := call(rev, "GET", "/console/api/dimensions?dim=ip", ""); code != 400 {
		t.Errorf("bad dim %d", code)
	}
	body := `{"key":"aaaaaaaaaaaaaaaa","name":"alice-codex"}`
	if code, _ := call(rev, "POST", "/console/api/aliases", body); code != 403 {
		t.Errorf("reviewer alias %d", code)
	}
	if code, _ := call(shared, "POST", "/console/api/aliases", body); code != 403 {
		t.Errorf("shared alias %d", code)
	}
	if code, _ := call(adm, "POST", "/console/api/aliases", `{"key":"zz","name":"x"}`); code != 400 {
		t.Errorf("bad alias %d", code)
	}
	if code, _ := call(adm, "POST", "/console/api/aliases", body); code != 200 || st.Aliases()["aaaaaaaaaaaaaaaa"].By != "adm" {
		t.Errorf("admin alias %d %+v", code, st.Aliases())
	}
}
