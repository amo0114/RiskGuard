package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"riskguard/internal/classifier"
	"riskguard/internal/config"
	"riskguard/internal/console"
	"riskguard/internal/policy"
	"riskguard/internal/proxy"
)

// Doctor results. NOT_VERIFIED is a first-class answer: a check this run could not or did not
// perform is never reported as passing.
const (
	docPass        = "PASS"
	docWarn        = "WARN"
	docFail        = "FAIL"
	docNotVerified = "NOT_VERIFIED"
)

// probeText is benign and synthetic; it is the only classifier input doctor ever sends.
const probeText = "Please write a unit test for a function that adds two integers."

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type doctor struct {
	w      io.Writer
	failed bool
	client *http.Client
}

func (d *doctor) report(status, check, detail string) {
	if status == docFail {
		d.failed = true
	}
	fmt.Fprintf(d.w, "%-12s %-22s %s\n", status, check, detail)
}

// runDoctor checks a deployment without changing it: no file is written or removed, no setting
// is switched, and nothing is sent anywhere unless probe is set. With probe it sends one
// synthetic classifier request and one GET per entry URL. Exit code 1 when any check fails.
func runDoctor(w io.Writer, cfgPath string, probe bool, entries []string) int {
	d := &doctor{w: w, client: &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil}, // probes must hit the named host, never a proxy
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	cfg, sec, err := config.Load(cfgPath)
	if err != nil {
		d.report(docFail, "config", fmt.Sprintf("%s: %v", cfgPath, err))
		d.report(docNotVerified, "everything else", "fix the config first")
		return 1
	}
	d.report(docPass, "config", fmt.Sprintf("%s (mode %s; listeners and classifier endpoint validated)", cfgPath, cfg.Mode))
	d.checkPolicy(cfg)
	d.checkSecretFiles(cfg)
	d.checkStateDirs(cfg)
	if cfg.Console.AccountsFile != "" {
		if accts, err := console.LoadAccounts(cfg.Console.AccountsFile); err != nil {
			d.report(docFail, "console accounts", err.Error())
		} else {
			d.report(docPass, "console accounts", fmt.Sprintf("%d named account(s)", len(accts)))
		}
	}
	d.checkRunning(cfg)
	d.checkUpstream(cfg)

	switch {
	case cfg.Mode == "disabled":
		d.report(docNotVerified, "classifier probe", "mode disabled: no classifier in use")
	case !probe:
		d.report(docNotVerified, "classifier probe", "not sent; run with -doctor-probe to send one synthetic request")
	default:
		d.probeClassifier(cfg, sec)
	}
	if probe {
		for _, u := range entries {
			d.probeEntry(u)
		}
	} else if len(entries) > 0 {
		d.report(docNotVerified, "entry probes", "-probe-url given without -doctor-probe; nothing sent")
	}
	d.report(docNotVerified, "entry completeness",
		"no tool can prove that every domain, port, WebSocket or direct path to New API goes through Guard; list each public entry and probe it")
	if d.failed {
		return 1
	}
	return 0
}

func (d *doctor) checkPolicy(cfg *config.Config) {
	pol, err := policy.Load(cfg.PolicyFile)
	switch {
	case err != nil && cfg.Mode == "disabled":
		// Not loaded while review is off (-check passes); it would fail once shadow/enforce is on.
		d.report(docWarn, "policy", "not used while disabled, but would fail to load once review is enabled: "+err.Error())
		return
	case err != nil:
		d.report(docFail, "policy", err.Error())
		return
	case cfg.Mode == "disabled":
		d.report(docNotVerified, "policy", pol.Version+" loads, but is not used while disabled")
		return
	}
	draft := strings.HasSuffix(pol.Version, "-draft")
	switch {
	case draft && cfg.Mode == "enforce":
		d.report(docFail, "policy", pol.Version+" is a draft; enforce refuses to start with it")
	case draft:
		d.report(docWarn, "policy", pol.Version+" is a draft: fine for shadow, enforce would refuse it")
	default:
		d.report(docPass, "policy", pol.Version)
	}
	if len(pol.T0OnlyProtocols) > 0 {
		d.report(docWarn, "policy exemptions", "forwarded without content review: "+strings.Join(pol.T0OnlyProtocols, ", "))
	}
	if len(pol.CoverageExceptions) > 0 {
		d.report(docWarn, "coverage exceptions", "uninspectable but forwarded in enforce (not protected): "+strings.Join(pol.CoverageExceptions, ", "))
	}
}

// checkSecretFiles looks at modes only; contents were already validated by config.Load and are
// never printed.
func (d *doctor) checkSecretFiles(cfg *config.Config) {
	files := []string{cfg.HMACKeyFile, cfg.ModelGuard.APIKeyFile, cfg.Console.TokenFile, cfg.Console.AccountsFile, cfg.AuxJudge.APIKeyFile}
	if cfg.Samples.Enabled {
		files = append(files, cfg.Samples.EncryptionKeyFile, cfg.Samples.DedupKeyFile)
	}
	var bad, loose []string
	n := 0
	for _, f := range files {
		if f == "" {
			continue
		}
		fi, err := os.Stat(f)
		if err != nil {
			bad = append(bad, f+": "+err.Error())
			continue
		}
		n++
		switch m := fi.Mode().Perm(); {
		case m&0o007 != 0:
			bad = append(bad, fmt.Sprintf("%s is accessible to all users (%#o)", f, m))
		case m&0o020 != 0:
			loose = append(loose, fmt.Sprintf("%s is group-writable (%#o)", f, m))
		}
	}
	switch {
	case len(bad) > 0:
		d.report(docFail, "secret files", strings.Join(bad, "; "))
	case len(loose) > 0:
		d.report(docWarn, "secret files", strings.Join(loose, "; "))
	default:
		d.report(docPass, "secret files", fmt.Sprintf("%d file(s) with no permissions for other users; group access follows the deployment's trust boundary", n))
	}
}

func (d *doctor) checkStateDirs(cfg *config.Config) {
	dirs := []string{cfg.Request.SpoolDir}
	if cfg.Console.StateFile != "" {
		dirs = append(dirs, filepath.Dir(cfg.Console.StateFile))
	}
	if cfg.Samples.Enabled {
		dirs = append(dirs, filepath.Dir(cfg.Samples.Path))
	}
	var bad, missing []string
	for _, dir := range dirs {
		fi, err := os.Stat(dir)
		switch {
		case errors.Is(err, os.ErrNotExist):
			missing = append(missing, dir)
		case err != nil:
			bad = append(bad, dir+": "+err.Error())
		case !fi.IsDir():
			bad = append(bad, dir+" is not a directory")
		case fi.Mode().Perm()&0o002 != 0:
			bad = append(bad, fmt.Sprintf("%s is world-writable (%#o)", dir, fi.Mode().Perm()))
		}
	}
	switch {
	case len(bad) > 0:
		d.report(docFail, "state directories", strings.Join(bad, "; "))
	case len(missing) > 0:
		d.report(docWarn, "state directories", "not created yet (the service creates them on start): "+strings.Join(missing, ", "))
	default:
		d.report(docPass, "state directories", strings.Join(dirs, ", "))
	}
}

// checkRunning reads the running instance's own loopback health endpoints.
func (d *doctor) checkRunning(cfg *config.Config) {
	base := "http://" + cfg.AdminListener
	var ready struct{ Status, Mode string }
	if err := d.getJSON(base+"/__risk/readyz", &ready); err != nil {
		d.report(docWarn, "running instance", "no answer on "+cfg.AdminListener+" (not running, or not reachable from here): "+err.Error())
		d.report(docNotVerified, "classifier health", "no running instance to ask")
		return
	}
	if ready.Status != "ready" {
		d.report(docWarn, "running instance", fmt.Sprintf("answered but reports status %q, not ready", ready.Status))
	} else if ready.Mode != cfg.Mode {
		d.report(docWarn, "running instance", fmt.Sprintf("running in %s but the config says %s: restart to apply", ready.Mode, cfg.Mode))
	} else {
		d.report(docPass, "running instance", "ready, mode "+ready.Mode)
	}
	var h struct {
		Status            string    `json:"status"`
		LastOK            time.Time `json:"last_ok"`
		LastFailure       time.Time `json:"last_failure"`
		LastFailureStatus string    `json:"last_failure_status"`
	}
	if err := d.getJSON(base+"/__risk/classifier", &h); err != nil {
		d.report(docWarn, "classifier health", err.Error())
		return
	}
	switch {
	case h.Status == "disabled":
		d.report(docNotVerified, "classifier health", "guard disabled")
	case h.LastOK.IsZero() && h.LastFailure.IsZero():
		d.report(docNotVerified, "classifier health", "no classification since start")
	case h.LastFailure.After(h.LastOK):
		d.report(docWarn, "classifier health", fmt.Sprintf("last call failed (%s) at %s; last success %s",
			h.LastFailureStatus, h.LastFailure.Format(time.RFC3339), stamp(h.LastOK)))
	default:
		d.report(docPass, "classifier health", "last recorded success "+stamp(h.LastOK)+"; not a live check (-doctor-probe sends one)")
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%s (%s ago)", t.Format(time.RFC3339), time.Since(t).Round(time.Second))
}

// checkUpstream asks New API for its public status page: a read-only local request.
func (d *doctor) checkUpstream(cfg *config.Config) {
	resp, err := d.client.Get(strings.TrimRight(cfg.NewAPI, "/") + "/api/status")
	if err != nil {
		d.report(docWarn, "upstream", cfg.NewAPI+" not reachable: "+err.Error())
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		d.report(docWarn, "upstream", fmt.Sprintf("%s/api/status returned %d", cfg.NewAPI, resp.StatusCode))
		return
	}
	d.report(docPass, "upstream", cfg.NewAPI+" answers /api/status")
}

func (d *doctor) probeClassifier(cfg *config.Config, sec *config.Secrets) {
	g := cfg.ModelGuard
	ctx, cancel := context.WithTimeout(context.Background(), g.Timeout)
	defer cancel()
	res := classifier.NewQwen(g.Endpoint, g.Model, sec.GuardAPIKey, g.MaxTokens).Moderate(ctx, probeText)
	took := res.Duration.Round(time.Millisecond)
	switch {
	case res.Status != "ok":
		d.report(docFail, "classifier probe", fmt.Sprintf("%s: status %s after %s", g.Endpoint, res.Status, took))
	case res.Label != classifier.Safe:
		d.report(docWarn, "classifier probe", fmt.Sprintf("answered in %s but labelled a benign synthetic request %s %v", took, res.Label, res.Categories))
	default:
		d.report(docPass, "classifier probe", fmt.Sprintf("%s answered Safe in %s (one synthetic request)", res.ModelID, took))
	}
}

// entryURL accepts only a plain http(s) URL: no user info (Go would send it as Basic auth), no
// query or fragment (tokens travel there). shown is safe to print in either case.
func entryURL(raw string) (u *url.URL, shown string, err error) {
	u, err = url.Parse(raw)
	if err != nil {
		return nil, "(unparseable URL)", errors.New("not a URL")
	}
	shown = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, shown, errors.New("only http and https are probed")
	case u.Host == "":
		return nil, shown, errors.New("no host")
	case u.User != nil:
		return nil, shown, errors.New("user info would be sent as credentials; the probe is unauthenticated")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return nil, shown, errors.New("query and fragment may carry tokens; give a plain path such as /api/status")
	}
	return u, shown, nil
}

// probeEntry sends one unauthenticated GET. The trace header shows the response passed through
// something that sets it, normally a Risk Guard; it is an observation, not proof of origin, and
// says nothing about other entries.
func (d *doctor) probeEntry(raw string) {
	u, shown, err := entryURL(raw)
	if err != nil {
		d.report(docFail, "entry probe", shown+": not sent: "+err.Error())
		return
	}
	resp, err := d.client.Get(u.String())
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the cause without the URL
		}
		d.report(docFail, "entry probe", shown+": "+err.Error())
		return
	}
	resp.Body.Close()
	if resp.Header.Get(proxy.TraceHeader) == "" {
		d.report(docFail, "entry probe", fmt.Sprintf("%s answered %d without %s: this entry does not go through Guard", shown, resp.StatusCode, proxy.TraceHeader))
		return
	}
	d.report(docPass, "entry probe", fmt.Sprintf("%s answered %d with %s observed (an observation, not proof of origin)", shown, resp.StatusCode, proxy.TraceHeader))
}

func (d *doctor) getJSON(u string, v any) error {
	resp, err := d.client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(v)
}
