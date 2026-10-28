package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"riskguard/internal/audit"
	"riskguard/internal/classifier"
	"riskguard/internal/config"
	"riskguard/internal/console"
	"riskguard/internal/extract"
	"riskguard/internal/limits"
	"riskguard/internal/policy"
	"riskguard/internal/proxy"
	"riskguard/internal/samples"
)

func main() {
	cfgPath := flag.String("config", "/etc/riskguard/config.yaml", "config file")
	checkOnly := flag.Bool("check", false, "validate config and policy, then exit")
	newAccount := flag.String("new-account", "", "print a new console account token and its accounts_file entry, then exit")
	roles := flag.String("roles", "", "comma-separated roles for -new-account: reviewer, admin")
	exportDir := flag.String("export-dataset", "", "write labeled samples to this new directory as rgeval scenarios, then exit")
	doctorRun := flag.Bool("doctor", false, "check the deployment read-only (config, policy, file modes, running instance, upstream), then exit")
	doctorProbe := flag.Bool("doctor-probe", false, "with -doctor: also send one synthetic classifier request and GET each -probe-url")
	var probeURLs stringList
	flag.Var(&probeURLs, "probe-url", "with -doctor-probe: a public entry URL to check for the trace header (repeatable)")
	flag.Parse()
	if *doctorRun {
		os.Exit(runDoctor(os.Stdout, *cfgPath, *doctorProbe, probeURLs))
	}
	if *newAccount != "" {
		var rs []string
		if *roles != "" {
			rs = strings.Split(*roles, ",")
		}
		token, entry, err := console.NewAccount(*newAccount, rs)
		if err != nil {
			log.Fatalf("riskguard: %v", err)
		}
		// The token goes to stderr so the entry can be piped into the accounts file on its own.
		fmt.Fprintf(os.Stderr, "console token for %s (shown once, store it in a password manager):\n%s\n", *newAccount, token)
		fmt.Print(entry)
		return
	}

	cfg, sec, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("riskguard: config: %v", err)
	}
	upstream, _ := url.Parse(cfg.NewAPI) // validated in config.Load
	auditLog := audit.New(os.Stdout, sec.HMACKey)

	// -check and -export-dataset stop before buildGuard: they validate the same policy but must
	// not create the spool pool, whose constructor cleans the spool directory a running instance
	// may be using.
	var pol *policy.Policy
	if cfg.Mode != "disabled" {
		if pol, err = loadPolicy(cfg); err != nil {
			log.Fatalf("riskguard: %v", err)
		}
	}
	var accounts []console.Account
	if cfg.Console.AccountsFile != "" {
		if accounts, err = console.LoadAccounts(cfg.Console.AccountsFile); err != nil {
			log.Fatalf("riskguard: console accounts: %v", err)
		}
	}
	if *checkOnly {
		fmt.Println("config ok")
		return
	}
	if *exportDir != "" {
		if !cfg.Samples.Enabled {
			log.Fatal("riskguard: -export-dataset needs samples.enabled")
		}
		st, err := samples.Open(cfg.Samples, sec.SampleKey, sec.SampleDedup)
		if err != nil {
			log.Fatalf("riskguard: samples: %v", err)
		}
		n, err := exportDataset(st, *exportDir, time.Now())
		result := fmt.Sprintf("items=%d", n)
		if err != nil {
			result = "failed"
		}
		if aerr := st.Audit("cli", "export_dataset", *exportDir, result); aerr != nil {
			log.Printf("riskguard: access audit: %v", aerr)
		}
		st.Close()
		if err != nil {
			log.Fatalf("riskguard: export: %v", err)
		}
		fmt.Printf("exported %d labeled samples to %s\n", n, *exportDir)
		return
	}
	var guard *proxy.Guard
	if pol != nil {
		if guard, err = buildGuard(cfg, sec, auditLog, pol); err != nil {
			log.Fatalf("riskguard: %v", err)
		}
	}
	// A sample store that cannot open only disables collection; the Guard keeps protecting.
	var collector *samples.Collector
	var samplesErr string
	if cfg.Samples.Enabled {
		if st, err := samples.Open(cfg.Samples, sec.SampleKey, sec.SampleDedup); err != nil {
			log.Printf("riskguard: samples disabled: %v", err)
			samplesErr = "store unavailable: " + err.Error()
		} else {
			collector = samples.NewCollector(cfg.Samples, st)
		}
	}

	var stats *console.Stats
	if cfg.Console.TokenFile != "" {
		stats = loadConsoleStats(cfg.Console.StateFile)
		auditLog.OnLog = stats.Add
	}

	h := proxy.New(upstream, proxy.Options{Mode: cfg.Mode, MaxBody: cfg.Request.MaxBodyBytes, Audit: auditLog, Guard: guard, Samples: collector})
	srv := &http.Server{
		Addr:              cfg.Listener,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No ReadTimeout/WriteTimeout: they would cap long SSE responses and large uploads.
	}

	// Health lives on its own loopback listener so OpenResty can never route public traffic to it.
	// readyz is local readiness only; classifier state is reported separately and never fails
	// readiness, so a remote outage cannot trigger systemd restart loops.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__risk/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /__risk/readyz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"status":"ready","mode":%q}`, cfg.Mode)
	})
	mux.HandleFunc("GET /__risk/classifier", func(w http.ResponseWriter, _ *http.Request) {
		if guard == nil {
			w.Write([]byte(`{"status":"disabled"}`))
			return
		}
		json.NewEncoder(w).Encode(guard.ClassifierHealth())
	})
	persistStop, persistDone := make(chan struct{}), make(chan struct{})
	if stats != nil {
		r, g := cfg.Request, cfg.ModelGuard
		info := console.Info{Mode: cfg.Mode, Model: g.Model, StartedAt: time.Now(), AuditFailures: auditLog.Failures,
			Accounts: accounts, Samples: collector, SamplesError: samplesErr,
			Settings: map[string]any{
				"max_body_bytes": r.MaxBodyBytes, "spool_max_total_bytes": r.SpoolMaxTotalBytes, "spool_max_files": r.SpoolMaxFiles,
				"spool_max_memory_bytes": r.SpoolMaxMemoryBytes,
				"extract_concurrency":    r.ExtractConcurrency, "primary_budget_bytes": r.PrimaryBudgetBytes,
				"context_budget_bytes": r.ContextBudgetBytes, "review_per_ip_per_minute": r.PerIPPerMinute,
				"review_per_credential_per_minute": r.PerCredentialPerMin, "classifier_timeout": g.Timeout.String(),
				"classifier_max_concurrency": g.MaxConcurrency, "classifier_max_queue": g.MaxQueue,
				"classifier_queue_wait": g.QueueWait.String(), "cache_ttl": g.CacheTTL.String(), "cache_entries": g.CacheEntries,
			}}
		if guard != nil {
			info.PolicyVersion, info.Health, info.Policy = guard.Policy.Version, guard.ClassifierHealth, guard.Policy
			guard.BlockReplyOn.Store(stats.BlockReply())
			info.BlockReply = &guard.BlockReplyOn
		}
		console.New(stats, sec.ConsoleToken, cfg.Console.SessionTTL, info).Register(mux)
		go func() {
			defer close(persistDone)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-persistStop:
					return
				case <-ticker.C:
					if err := stats.Save(); err != nil {
						log.Printf("riskguard: console state save: %v", err)
					}
				}
			}
		}()
	}
	admin := &http.Server{Addr: cfg.AdminListener, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServe() }()
	go func() { errc <- admin.ListenAndServe() }()
	log.Printf("riskguard: mode=%s listen=%s admin=%s upstream=%s", cfg.Mode, cfg.Listener, cfg.AdminListener, cfg.NewAPI)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("riskguard: %v", err)
		}
	case s := <-sig:
		log.Printf("riskguard: %v, draining", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = admin.Shutdown(ctx)
	// Drain below tracks WebSocket audits and closes their tunnels if the grace period expires.
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("riskguard: shutdown: %v", err)
		_ = srv.Close()
	}
	if err := h.Drain(ctx); err != nil {
		log.Printf("riskguard: audit drain: %v; cancelling shadow work", err)
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		if err := h.Drain(cleanup); err != nil {
			log.Printf("riskguard: audit drain incomplete: %v", err)
		}
		stop()
	}
	// Samples are offered as audits are written, so the collector closes after the drain.
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	collector.Close(sctx)
	scancel()
	if stats != nil {
		close(persistStop)
		<-persistDone
		if err := stats.Save(); err != nil {
			log.Printf("riskguard: console state save: %v", err)
		}
	}
}

func loadConsoleStats(path string) *console.Stats {
	stats, err := console.NewStats(path)
	if err == nil {
		return stats
	}
	log.Printf("riskguard: console state %s unavailable: %v; using memory-only statistics, original file preserved", path, err)
	stats, _ = console.NewStats("")
	return stats
}

func loadPolicy(cfg *config.Config) (*policy.Policy, error) {
	pol, err := policy.Load(cfg.PolicyFile)
	if err != nil {
		return nil, err
	}
	if cfg.Mode == "enforce" && strings.HasSuffix(pol.Version, "-draft") {
		return nil, fmt.Errorf("policy %s is a draft; enforce requires an approved policy", pol.Version)
	}
	return pol, nil
}

// buildGuard creates the runtime resources, including the spool pool (which removes leftover
// spool files): only for the process that will serve traffic.
func buildGuard(cfg *config.Config, sec *config.Secrets, a *audit.Logger, pol *policy.Policy) (*proxy.Guard, error) {
	r, g := cfg.Request, cfg.ModelGuard
	sp, err := proxy.NewSpoolPool(r.SpoolDir, r.MemorySpoolBytes, r.SpoolMaxTotalBytes, r.SpoolMaxFiles, proxy.WithSpoolMemoryLimit(r.SpoolMaxMemoryBytes))
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	guard := &proxy.Guard{
		Policy:            pol,
		Classifier:        classifier.NewQwen(g.Endpoint, g.Model, sec.GuardAPIKey, g.MaxTokens),
		ModelID:           g.Model,
		Spool:             sp,
		Budget:            extract.Budget{Primary: r.PrimaryBudgetBytes, Context: r.ContextBudgetBytes},
		ExtractGate:       limits.NewGate(r.ExtractConcurrency, r.ExtractQueue),
		ClassifierGate:    limits.NewGate(g.MaxConcurrency, g.MaxQueue),
		QueueWait:         g.QueueWait,
		ClassifierTimeout: g.Timeout,
		AttemptTimeout:    g.AttemptTimeout,
		PerIP:             limits.NewKeyedRate(r.PerIPPerMinute, 10000),
		PerCredential:     limits.NewKeyedRate(r.PerCredentialPerMin, 10000),
		Cache:             proxy.NewCache(g.CacheTTL, g.CacheEntries),
		Fingerprint:       a.Fingerprint,
	}
	if j := cfg.AuxJudge; j.Endpoint != "" {
		guard.Judge = classifier.NewJudge(j.Endpoint, j.Model, sec.AuxJudgeKey, false)
		guard.JudgeGate = limits.NewGate(j.MaxConcurrency, 0)
		guard.JudgeTimeout = j.Timeout
	}
	return guard, nil
}
