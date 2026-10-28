// Package policy turns classifier evidence and coverage facts into a decision. policy-v1.yaml is
// the source of truth; shadow and enforce use the same Decide and differ only in Action.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"

	"riskguard/internal/classifier"
)

const (
	Allow       = "allow"
	Review      = "review"
	Deny        = "deny"
	Unavailable = "unavailable"
	Unsupported = "unsupported"
)

type Policy struct {
	Version          string            `yaml:"version"`
	Labels           map[string]string `yaml:"labels"`
	UnsafeCategories map[string]string `yaml:"unsafe_categories"`
	UnsafeDefault    string            `yaml:"unsafe_default"`
	// T0OnlyProtocols are model_text protocols the user approved to forward without content review.
	T0OnlyProtocols []string `yaml:"t0_only_protocols"`
	// CoverageExceptions are uninspectable/unknown protocols or path templates the user approved to
	// forward in enforce mode. Listing one here never makes it "protected".
	CoverageExceptions []string `yaml:"coverage_exceptions"`
	Enforce            struct {
		Review             string `yaml:"review"`               // reject | forward
		NoInspectableInput string `yaml:"no_inspectable_input"` // reject | forward
		Unparseable        string `yaml:"unparseable"`          // reject | forward
		// BlockReplies, when non-empty, answers deny/review rejections as an ordinary assistant
		// turn carrying one of these texts (OpenAI chat and Claude messages only).
		BlockReplies []string `yaml:"block_replies"`
	} `yaml:"enforce"`
}

func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &p, p.validate()
}

func (p *Policy) validate() error {
	if p.Version == "" {
		return errors.New("policy: version required")
	}
	for _, l := range []string{classifier.Safe, classifier.Controversial, classifier.Unknown} {
		if !oneOf(p.Labels[l], Allow, Review, Deny) {
			return fmt.Errorf("policy: labels.%s must be allow|review|deny", l)
		}
	}
	if !oneOf(p.UnsafeDefault, Review, Deny) {
		return errors.New("policy: unsafe_default must be review|deny")
	}
	for c, a := range p.UnsafeCategories {
		if !oneOf(a, Allow, Review, Deny) {
			return fmt.Errorf("policy: unsafe_categories.%s must be allow|review|deny", c)
		}
		known := false
		for _, k := range classifier.KnownCategories {
			known = known || k == c
		}
		if !known {
			return fmt.Errorf("policy: unknown category %q", c)
		}
	}
	for name, v := range map[string]string{"review": p.Enforce.Review, "no_inspectable_input": p.Enforce.NoInspectableInput, "unparseable": p.Enforce.Unparseable} {
		if !oneOf(v, "reject", "forward") {
			return fmt.Errorf("policy: enforce.%s must be reject|forward", name)
		}
	}
	return nil
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

type Decision struct {
	Decision string
	Reason   string
}

// T0Only reports whether a model_text protocol is an approved forward-without-review exception.
func (p *Policy) T0Only(protocol string) bool { return oneOf(protocol, p.T0OnlyProtocols...) }

// Excepted reports whether an uninspectable/unknown request is an approved coverage exception.
func (p *Policy) Excepted(protocol, template string) bool {
	return (protocol != "" && oneOf(protocol, p.CoverageExceptions...)) || oneOf(template, p.CoverageExceptions...)
}

// Classified maps a classifier result to a decision.
func (p *Policy) Classified(r classifier.Result) Decision {
	switch r.Status {
	case "ok":
	case "parse_failed":
		return Decision{p.Labels[classifier.Unknown], "PARSE_FAILED"}
	case "too_long":
		return Decision{p.Labels[classifier.Unknown], "INPUT_TOO_LONG"}
	case "timeout":
		return Decision{Unavailable, "MODEL_TIMEOUT"}
	case "busy":
		return Decision{Unavailable, "CLASSIFIER_BUSY"}
	default:
		return Decision{Unavailable, "MODEL_UNAVAILABLE"}
	}
	switch r.Label {
	case classifier.Safe:
		return Decision{p.Labels[classifier.Safe], "CLASSIFIER_SAFE"}
	case classifier.Controversial:
		return Decision{p.Labels[classifier.Controversial], "AMBIGUOUS"}
	case classifier.Unsafe:
		if len(r.Categories) == 0 {
			return Decision{p.UnsafeDefault, "POLICY_UNSAFE_UNCATEGORISED"}
		}
		worst := Allow
		for _, c := range r.Categories {
			a, ok := p.UnsafeCategories[c]
			if !ok {
				a = p.UnsafeDefault
			}
			if rank(a) > rank(worst) {
				worst = a
			}
		}
		reason := map[string]string{Deny: "POLICY_HIGH_RISK", Review: "POLICY_REVIEW", Allow: "POLICY_ALLOWED_CATEGORY"}[worst]
		return Decision{worst, reason}
	}
	return Decision{p.Labels[classifier.Unknown], "UNKNOWN_LABEL"}
}

func rank(a string) int {
	switch a {
	case Deny:
		return 2
	case Review:
		return 1
	}
	return 0
}

// Action is what enforce mode does with a decision: forward, or reject with status/code.
type Action struct {
	Forward bool
	Status  int
	Code    string
	Message string
}

func (p *Policy) Action(d Decision) Action {
	switch d.Decision {
	case Allow:
		return Action{Forward: true}
	case Deny:
		return Action{Status: http.StatusForbidden, Code: "POLICY_DISALLOWED", Message: "request blocked by content policy"}
	case Review:
		if p.Enforce.Review == "forward" {
			return Action{Forward: true}
		}
		return Action{Status: http.StatusUnprocessableEntity, Code: "REVIEW_REQUIRED", Message: "request needs review under content policy"}
	case Unavailable:
		return Action{Status: http.StatusServiceUnavailable, Code: "GUARD_UNAVAILABLE", Message: "content guard temporarily unavailable"}
	case Unsupported:
		var setting string
		switch d.Reason {
		case "NO_INSPECTABLE_INPUT", "NO_USER_TEXT":
			setting = p.Enforce.NoInspectableInput
		case "COVERAGE_GAP":
			return Action{Status: http.StatusForbidden, Code: "UNSUPPORTED_PROTOCOL", Message: "this endpoint is not available through the content guard"}
		case "MEDIA_ONLY": // image/audio-only generation input: nothing the text classifier can review
			return Action{Status: http.StatusForbidden, Code: "UNSUPPORTED_PROTOCOL", Message: "media-only requests cannot be reviewed by the content guard"}
		default:
			setting = p.Enforce.Unparseable
		}
		if setting == "forward" {
			return Action{Forward: true}
		}
		return Action{Status: http.StatusBadRequest, Code: "UNSUPPORTED_PROTOCOL", Message: "request body could not be inspected"}
	}
	return Action{Status: http.StatusServiceUnavailable, Code: "GUARD_UNAVAILABLE", Message: "content guard error"}
}
