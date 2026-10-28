package console

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"riskguard/internal/audit"
)

// Dimensions the console can group guarded events by.
const (
	DimCredential = "credential"
	DimClient     = "client"
	DimModel      = "model"
	// dimCap bounds distinct values per dimension per hour; the rest is counted under dimOther.
	// Fingerprints are taken before New API authenticates, so random keys must not grow memory or
	// the snapshot without bound (worst case ~7 days x 3 x 100 rows).
	dimCap   = 100
	dimOther = "(other)"
)

var dims = []string{DimCredential, DimClient, DimModel}

// dimRow aggregates one hour of guarded events for one key, client or model.
type dimRow struct {
	Requests   int            `json:"req"`
	Decisions  map[string]int `json:"decisions,omitempty"`
	WouldBlock int            `json:"would_block,omitempty"`
	Enforced   int            `json:"enforced,omitempty"`
	ClsErrors  int            `json:"cls_errors,omitempty"`
	Categories map[string]int `json:"categories,omitempty"`
	Last       int64          `json:"last"`
}

type dimHour struct {
	Hour int64                         `json:"h"`
	Dims map[string]map[string]*dimRow `json:"dims"`
}

// Alias is an admin's label for a credential fingerprint ("alice-codex"): the console maps
// fingerprints to people only through what an admin wrote here.
type Alias struct {
	Name string    `json:"name"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
}

func dimValue(e audit.Event, dim string) string {
	switch dim {
	case DimCredential:
		return e.CredentialHMAC
	case DimClient:
		return e.Client
	}
	return e.Model
}

// addDims is called by Add for guarded events; caller holds mu.
func (s *Stats) addDims(e audit.Event) {
	h := e.Timestamp.Unix() / 3600
	dh := s.dims[h]
	if dh == nil {
		dh = &dimHour{Hour: h, Dims: map[string]map[string]*dimRow{}}
		s.dims[h] = dh
	}
	for _, d := range dims {
		v := dimValue(e, d)
		if v == "" {
			v = "(none)"
		}
		m := dh.Dims[d]
		if m == nil {
			m = map[string]*dimRow{}
			dh.Dims[d] = m
		}
		row := m[v]
		if row == nil {
			if len(m) >= dimCap {
				v = dimOther
				row = m[v]
			}
			if row == nil {
				row = &dimRow{}
				m[v] = row
			}
		}
		row.Requests++
		inc(&row.Decisions, e.Decision)
		if e.WouldBlock {
			row.WouldBlock++
		}
		if e.Enforced {
			row.Enforced++
		}
		if e.ClassifierStatus != "" && e.ClassifierStatus != "ok" {
			row.ClsErrors++
		}
		for _, c := range e.Categories {
			inc(&row.Categories, c)
		}
		if t := e.Timestamp.Unix(); t > row.Last {
			row.Last = t
		}
	}
}

// DimSummary is one value of a dimension over a time range.
type DimSummary struct {
	Key        string         `json:"key"`
	Alias      string         `json:"alias,omitempty"`
	Requests   int            `json:"requests"`
	Decisions  map[string]int `json:"decisions"`
	WouldBlock int            `json:"would_block"`
	Enforced   int            `json:"enforced"`
	ClsErrors  int            `json:"cls_errors"`
	Categories []kv           `json:"categories"`
	LastSeen   int64          `json:"last_seen"`
}

// Dimension sums whole hours overlapping the window, so "1h" covers up to two clock hours.
// Aliases are included only when withAliases (sessions with a role).
func (s *Stats) Dimension(dim string, window time.Duration, withAliases bool) []DimSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := s.now().Add(-window).Unix() / 3600
	acc := map[string]*DimSummary{}
	cats := map[string]map[string]int{}
	for h, dh := range s.dims {
		if h < first {
			continue
		}
		for v, row := range dh.Dims[dim] {
			a := acc[v]
			if a == nil {
				a = &DimSummary{Key: v, Decisions: map[string]int{}}
				acc[v], cats[v] = a, map[string]int{}
			}
			a.Requests += row.Requests
			a.WouldBlock += row.WouldBlock
			a.Enforced += row.Enforced
			a.ClsErrors += row.ClsErrors
			for k, n := range row.Decisions {
				a.Decisions[k] += n
			}
			for k, n := range row.Categories {
				cats[v][k] += n
			}
			a.LastSeen = max(a.LastSeen, row.Last)
		}
	}
	out := make([]DimSummary, 0, len(acc))
	for v, a := range acc {
		if a.Categories = sorted(cats[v]); len(a.Categories) > 3 {
			a.Categories = a.Categories[:3]
		}
		if withAliases && dim == DimCredential {
			a.Alias = s.aliases[v].Name
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Key < out[j].Key
	})
	return out
}

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

var ErrBadAlias = errors.New("alias needs a 16-hex fingerprint and a name of at most 40 characters")

// SetAlias names a credential fingerprint; an empty name removes it. Saved immediately.
func (s *Stats) SetAlias(key, name, by string) error {
	name = strings.TrimSpace(name)
	if !fingerprintRE.MatchString(key) || utf8.RuneCountInString(name) > 40 || strings.ContainsAny(name, "\r\n\t") {
		return ErrBadAlias
	}
	s.mu.Lock()
	if name == "" {
		delete(s.aliases, key)
	} else {
		s.aliases[key] = Alias{Name: name, By: by, At: s.now().UTC()}
	}
	s.mu.Unlock()
	return s.Save()
}

func (s *Stats) Aliases() map[string]Alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Alias, len(s.aliases))
	for k, v := range s.aliases {
		out[k] = v
	}
	return out
}
