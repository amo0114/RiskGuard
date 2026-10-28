package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"riskguard/internal/audit"
	"riskguard/internal/samples"
)

// Exercise the real main/signal/persistence lifecycle in a child test process.
func TestRiskguardProcess(t *testing.T) {
	if os.Getenv("RISKGUARD_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestStartupAndShadowAuditOnSIGTERM(t *testing.T) {
	for _, stateContent := range []string{"", "{broken", "null", "{}"} {
		damaged := stateContent != ""
		name := "pending-audit"
		if damaged {
			name = "corrupt-console-state-" + stateContent
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			cls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				close(started)
				<-release
				io.WriteString(w, `{"choices":[{"message":{"content":"Safety: Safe"},"finish_reason":"stop"}]}`)
			}))
			defer cls.Close()
			// Release a blocked mock even if a test assertion fails before SIGTERM.
			defer unblock()
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				io.WriteString(w, `{"ok":true}`)
			}))
			defer up.Close()
			work := t.TempDir()
			write := func(name, content string) string {
				path := filepath.Join(work, name)
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			state := filepath.Join(work, "state.json")
			if damaged {
				write("state.json", stateContent)
			}
			freeAddr := func() string {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := l.Addr().String()
				l.Close()
				return addr
			}
			listen, admin := freeAddr(), freeAddr()
			policy, _ := filepath.Abs("../../config/policy-v1.yaml")
			template, err := os.ReadFile("../../config/example.yaml")
			if err != nil {
				t.Fatal(err)
			}
			config := strings.NewReplacer(
				"127.0.0.1:4100", listen, "127.0.0.1:4101", admin,
				"http://127.0.0.1:4000", up.URL, "http://127.0.0.1:8088", cls.URL,
				"/etc/riskguard/hmac.key", write("hmac.key", strings.Repeat("h", 48)),
				"/etc/riskguard/guard.key", write("guard.key", "synthetic-key"),
				"/etc/riskguard/console.token", write("console.token", strings.Repeat("t", 40)),
				"/etc/riskguard/policy-v1.yaml", policy,
				"/var/lib/riskguard/console-stats.json", state,
				"/var/lib/riskguard/spool", filepath.Join(work, "spool"),
			).Replace(string(template))
			cfgPath := write("config.yaml", config)
			cmd := exec.Command(os.Args[0], "-test.run=^TestRiskguardProcess$", "--", "-config", cfgPath)
			cmd.Env = append(os.Environ(), "RISKGUARD_TEST_PROCESS=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() { cmd.Process.Kill() }()
			client := &http.Client{Timeout: time.Second}
			ready := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				resp, err := client.Get("http://" + admin + "/__risk/readyz")
				if err == nil {
					resp.Body.Close()
					ready = resp.StatusCode == 200
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("gateway failed to start")
			}
			resp, err := client.Post("http://"+listen+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"synthetic","messages":[{"role":"user","content":"safe synthetic text"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("forward: %d", resp.StatusCode)
			}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("classification did not start")
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				t.Fatalf("exited before pending audit completed: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("shutdown: %v; %s", err, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown did not finish")
			}
			var ev audit.Event
			if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &ev); err != nil || ev.HTTPStatus != 200 || ev.ClassifierStatus != "ok" {
				t.Fatalf("missing completed audit: %v %s", err, stdout.String())
			}
			raw, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			if damaged {
				if string(raw) != stateContent || !strings.Contains(stderr.String(), "memory-only statistics") {
					t.Fatal("damaged statistics were overwritten or warning was missing")
				}
			} else {
				var snap struct{ Events []audit.Event }
				if err := json.Unmarshal(raw, &snap); err != nil || len(snap.Events) != 1 || snap.Events[0].TraceID != ev.TraceID {
					t.Fatalf("final state saved before audit: %v %s", err, raw)
				}
			}
		})
	}
}

func TestExportDatasetWritesScenariosWithoutIdentifiers(t *testing.T) {
	dir := t.TempDir()
	cfg := samples.Config{
		Enabled: true, Path: filepath.Join(dir, "s", "samples.db"), EncryptionKeyFile: "e", DedupKeyFile: "d",
		MaxTextBytes: 1024, BaseProbability: 1, BaseDailyCap: 10, EnrichedDailyCap: 10,
		QueueItems: 4, QueueBytes: 1 << 20, QueueMaxAge: time.Second,
		ContentRetention: time.Hour, ReviewRetention: time.Hour, AuditRetention: time.Hour, MaxDBBytes: 1 << 26,
	}
	enc, dedup := bytes.Repeat([]byte("e"), 32), bytes.Repeat([]byte("d"), 32)
	st, err := samples.Open(cfg, enc, dedup)
	if err != nil {
		t.Fatal(err)
	}
	c := samples.NewCollector(cfg, st)
	e := audit.Event{TraceID: "rg-trace-1", Timestamp: time.Now(), Phase: "shadow", Protocol: "claude_messages",
		Decision: "allow", Label: "Safe", Coverage: "full_selected_inputs", CredentialHMAC: "c0ffeec0ffeec0ff", Client: "codex/1"}
	c.Offer(c.Candidate("how do I pick a lock", false), e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c.Close(ctx)
	cancel()
	if st, err = samples.Open(cfg, enc, dedup); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	list, _ := st.List(samples.Filter{})
	if _, err := st.AddReview(list[0].ID, "alice", "p1", samples.ReviewInput{Status: "labeled", ExpectedAction: "deny", Category: "Non-violent Illegal Acts"}); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "export")
	if n, err := exportDataset(st, out, time.Now()); err != nil || n != 1 {
		t.Fatalf("export = %d %v", n, err)
	}
	if _, err := exportDataset(st, out, time.Now()); err == nil {
		t.Error("export overwrote an existing directory")
	}
	raw, err := os.ReadFile(filepath.Join(out, "scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"rg-trace-1", "c0ffeec0ffeec0ff", "codex/1", "alice"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("export carries identifier %q", leak)
		}
	}
	var it datasetItem
	if err := json.Unmarshal(bytes.TrimSpace(raw), &it); err != nil {
		t.Fatal(err)
	}
	if it.Expect != "block" || it.Group != "samples-random" || it.Protocol != "openai_chat" || it.Source["original_protocol"] != "claude_messages" {
		t.Errorf("item = %+v", it)
	}
	var m struct {
		Items int               `json:"items"`
		Files map[string]string `json:"files"`
	}
	mb, _ := os.ReadFile(filepath.Join(out, "manifest.json"))
	sum := sha256.Sum256(raw)
	if json.Unmarshal(mb, &m) != nil || m.Items != 1 || m.Files["scenarios.jsonl"] != hex.EncodeToString(sum[:]) {
		t.Errorf("manifest = %s", mb)
	}
	for _, p := range []string{out, filepath.Join(out, "scenarios.jsonl"), filepath.Join(out, "manifest.json")} {
		if fi, _ := os.Stat(p); fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %v", p, fi.Mode().Perm())
		}
	}
}

// -check runs next to a live instance (upgrade pre-flight): it must validate without touching
// that instance's spool files, and still refuse a draft policy in enforce mode.
func TestCheckLeavesSpoolAlone(t *testing.T) {
	e := newDoctorEnv(t, "shadow", "Safe")
	live := filepath.Join(e.spool, "rg-spool-live")
	if err := os.WriteFile(live, []byte("in flight"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(cfg string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRiskguardProcess$", "--", "-config", cfg, "-check")
		cmd.Env = append(os.Environ(), "RISKGUARD_TEST_PROCESS=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(e.cfg); err != nil || !strings.Contains(out, "config ok") {
		t.Fatalf("-check: %v\n%s", err, out)
	}
	if _, err := os.Stat(live); err != nil {
		t.Error("-check removed a live spool file")
	}
	raw, _ := os.ReadFile(e.cfg)
	enforce := filepath.Join(e.dir, "enforce.yaml")
	os.WriteFile(enforce, []byte(strings.Replace(string(raw), `mode: "shadow"`, `mode: "enforce"`, 1)), 0o600)
	if out, err := run(enforce); err == nil || !strings.Contains(out, "draft") {
		t.Errorf("enforce with a draft policy passed -check:\n%s", out)
	}
}
