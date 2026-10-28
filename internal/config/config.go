package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"riskguard/internal/samples"
)

type Config struct {
	Listener      string `yaml:"listener"`
	AdminListener string `yaml:"admin_listener"`
	NewAPI        string `yaml:"new_api_upstream"`
	Mode          string `yaml:"mode"`
	Request       struct {
		MaxBodyBytes        int64  `yaml:"max_body_bytes"`
		MemorySpoolBytes    int64  `yaml:"memory_spool_threshold_bytes"`
		SpoolMaxMemoryBytes int64  `yaml:"spool_max_memory_bytes"`
		SpoolDir            string `yaml:"spool_dir"`
		SpoolMaxTotalBytes  int64  `yaml:"spool_max_total_bytes"`
		SpoolMaxFiles       int    `yaml:"spool_max_files"`
		ExtractConcurrency  int    `yaml:"extract_concurrency"`
		ExtractQueue        int    `yaml:"extract_queue"`
		PrimaryBudgetBytes  int    `yaml:"primary_budget_bytes"`
		ContextBudgetBytes  int    `yaml:"context_budget_bytes"`
		PerIPPerMinute      int    `yaml:"review_per_ip_per_minute"`
		PerCredentialPerMin int    `yaml:"review_per_credential_per_minute"`
	} `yaml:"request"`
	ModelGuard struct {
		Endpoint   string        `yaml:"endpoint"`
		Model      string        `yaml:"model"`
		APIKeyFile string        `yaml:"api_key_file"`
		Timeout    time.Duration `yaml:"timeout"`
		// AttemptTimeout (optional, < timeout) splits the timeout into two attempts: a call that
		// hangs, cannot connect or gets a 5xx is retried once with the time left. 0 = one attempt.
		AttemptTimeout time.Duration `yaml:"attempt_timeout"`
		MaxConcurrency int           `yaml:"max_concurrency"`
		MaxQueue       int           `yaml:"max_queue"`
		QueueWait      time.Duration `yaml:"queue_wait"`
		MaxTokens      int           `yaml:"max_tokens"`
		CacheTTL       time.Duration `yaml:"cache_ttl"`
		CacheEntries   int           `yaml:"cache_entries"`
	} `yaml:"model_guard"`
	// AuxJudge is an optional System One judge asked alongside the classifier in shadow mode only.
	// Its answers are logged for evaluation and never change a decision.
	AuxJudge struct {
		Endpoint       string        `yaml:"endpoint"`
		Model          string        `yaml:"model"`
		APIKeyFile     string        `yaml:"api_key_file"`
		Timeout        time.Duration `yaml:"timeout"`
		MaxConcurrency int           `yaml:"max_concurrency"`
	} `yaml:"aux_judge"`
	PolicyFile string `yaml:"policy_file"`
	// HMACKeyFile holds the audit fingerprint key; it lives outside the repo (0600).
	HMACKeyFile string `yaml:"hmac_key_file"`
	// Console is the read-only dashboard on the admin listener; an empty token_file disables it.
	Console struct {
		TokenFile  string        `yaml:"token_file"`
		StateFile  string        `yaml:"state_file"`
		SessionTTL time.Duration `yaml:"session_ttl"`
		// AccountsFile lists named accounts (riskguard -new-account); only they can see sample text.
		AccountsFile string `yaml:"accounts_file"`
	} `yaml:"console"`
	// Samples keeps redacted, encrypted copies of inspected text for human review; off by default.
	Samples samples.Config `yaml:"samples"`
}

type Secrets struct {
	HMACKey      []byte
	GuardAPIKey  string
	AuxJudgeKey  string
	ConsoleToken []byte
	SampleKey    []byte
	SampleDedup  []byte
}

func Load(path string) (*Config, *Secrets, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, nil, err
	}
	s := &Secrets{}
	if s.HMACKey, err = readSecret(c.HMACKeyFile); err != nil {
		return nil, nil, fmt.Errorf("hmac key: %w", err)
	}
	if len(s.HMACKey) < 32 {
		return nil, nil, errors.New("hmac key must be at least 32 bytes")
	}
	if c.Console.TokenFile != "" {
		if s.ConsoleToken, err = readSecret(c.Console.TokenFile); err != nil {
			return nil, nil, fmt.Errorf("console token: %w", err)
		}
		if len(s.ConsoleToken) < 32 {
			return nil, nil, errors.New("console token must be at least 32 bytes")
		}
	}
	if c.Mode != "disabled" {
		k, err := readSecret(c.ModelGuard.APIKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("model_guard api key: %w", err)
		}
		s.GuardAPIKey = string(k)
	}
	if c.Samples.Enabled {
		for _, k := range []struct {
			dst  *[]byte
			path string
		}{{&s.SampleKey, c.Samples.EncryptionKeyFile}, {&s.SampleDedup, c.Samples.DedupKeyFile}} {
			if *k.dst, err = readSecret(k.path); err != nil {
				return nil, nil, fmt.Errorf("samples key %s: %w", k.path, err)
			}
			if len(*k.dst) < 32 {
				return nil, nil, fmt.Errorf("samples key %s must be at least 32 bytes", k.path)
			}
		}
		if bytes.Equal(s.SampleKey, s.SampleDedup) || bytes.Equal(s.SampleKey, s.HMACKey) || bytes.Equal(s.SampleDedup, s.HMACKey) {
			return nil, nil, errors.New("samples keys must differ from each other and from the audit hmac key")
		}
	}
	if c.AuxJudge.Endpoint != "" {
		k, err := readSecret(c.AuxJudge.APIKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("aux_judge api key: %w", err)
		}
		s.AuxJudgeKey = string(k)
	}
	return &c, s, nil
}

func readSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, errors.New("empty")
	}
	return b, nil
}

func (c *Config) validate() error {
	for name, addr := range map[string]string{"listener": c.Listener, "admin_listener": c.AdminListener} {
		if err := requireLoopback(addr); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if c.Listener == c.AdminListener {
		return errors.New("admin_listener must differ from listener")
	}
	// The upstream is fixed config, never derived from a request: no open-proxy/SSRF surface.
	u, err := url.Parse(c.NewAPI)
	if err != nil || u.Scheme != "http" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return errors.New("new_api_upstream must be a bare http://host:port")
	}
	if err := requireLoopback(u.Host); err != nil {
		return fmt.Errorf("new_api_upstream: %w", err)
	}
	if c.Mode != "disabled" && c.Mode != "shadow" && c.Mode != "enforce" {
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if c.Request.MaxBodyBytes <= 0 {
		return errors.New("request.max_body_bytes must be > 0")
	}
	if c.HMACKeyFile == "" {
		return errors.New("hmac_key_file is required")
	}
	if c.Console.TokenFile != "" && (c.Console.StateFile == "" || c.Console.SessionTTL <= 0) {
		return errors.New("console: state_file and session_ttl are required with token_file")
	}
	if err := c.Samples.Validate(); err != nil {
		return err
	}
	if c.Samples.Enabled && (c.Mode == "disabled" || c.Console.TokenFile == "" || c.Console.AccountsFile == "") {
		return errors.New("samples: requires a guard mode and console token_file plus accounts_file (text is only shown to named accounts)")
	}
	if c.Mode == "disabled" {
		return nil
	}
	if c.Request.SpoolMaxMemoryBytes == 0 {
		c.Request.SpoolMaxMemoryBytes = 32 << 20 // backwards-compatible aggregate RAM default
	}

	r := c.Request
	if r.SpoolMaxMemoryBytes < 32<<10 || r.MemorySpoolBytes > r.SpoolMaxMemoryBytes-(32<<10) {
		return errors.New("request.spool_max_memory_bytes must cover memory_spool_threshold_bytes plus 32768 bytes of disk scratch space")
	}
	if r.SpoolDir == "" || r.MemorySpoolBytes <= 0 || r.SpoolMaxTotalBytes < r.MaxBodyBytes || r.SpoolMaxFiles <= 0 {
		return errors.New("request: spool_dir, memory_spool_threshold_bytes, spool_max_files required; spool_max_total_bytes >= max_body_bytes")
	}
	if r.ExtractConcurrency <= 0 || r.PrimaryBudgetBytes <= 0 || r.ContextBudgetBytes < 0 {
		return errors.New("request: extract_concurrency and primary_budget_bytes must be > 0")
	}
	g := c.ModelGuard
	eu, err := url.Parse(g.Endpoint)
	if err != nil || (eu.Scheme != "http" && eu.Scheme != "https") || eu.Path != "" || eu.User != nil {
		return errors.New("model_guard.endpoint must be a bare http(s)://host:port")
	}
	if err := requirePrivate(eu.Host); err != nil {
		return fmt.Errorf("model_guard.endpoint: %w", err)
	}
	if g.Model == "" || g.APIKeyFile == "" || g.Timeout <= 0 || g.MaxConcurrency <= 0 || g.MaxTokens <= 0 {
		return errors.New("model_guard: model, api_key_file, timeout, max_concurrency, max_tokens required")
	}
	if g.AttemptTimeout < 0 || (g.AttemptTimeout > 0 && g.AttemptTimeout >= g.Timeout) {
		return errors.New("model_guard.attempt_timeout must be 0 or shorter than timeout")
	}
	if c.PolicyFile == "" {
		return errors.New("policy_file is required")
	}
	if a := c.AuxJudge; a.Endpoint != "" {
		if c.Mode != "shadow" {
			return errors.New("aux_judge is shadow-only")
		}
		au, err := url.Parse(a.Endpoint)
		if err != nil || au.Scheme != "http" || au.Path != "" || au.User != nil {
			return errors.New("aux_judge.endpoint must be a bare http://host:port")
		}
		if err := requirePrivate(au.Host); err != nil {
			return fmt.Errorf("aux_judge.endpoint: %w", err)
		}
		if a.Model == "" || a.APIKeyFile == "" || a.Timeout <= 0 || a.MaxConcurrency <= 0 {
			return errors.New("aux_judge: model, api_key_file, timeout, max_concurrency required")
		}
	}
	return nil
}

func requireLoopback(hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%q is not a loopback IP address", hostport)
	}
	return nil
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// requirePrivate keeps classifier traffic (user text) on a private link: RFC1918, WireGuard or
// Tailscale (100.64/10), or loopback. A hostname is rejected so DNS cannot redirect it.
func requirePrivate(hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || cgnat.Contains(ip)) {
		return fmt.Errorf("%q is not a private IP address", hostport)
	}
	return nil
}
