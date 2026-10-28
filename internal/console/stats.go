package console

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"riskguard/internal/audit"
)

const (
	retention    = 7 * 24 * time.Hour
	recentEvents = 500
)

// latencyBounds are classifier latency histogram upper bounds in ms; the last bin is open-ended.
var latencyBounds = []int64{100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 8000, 12000}

// bucket aggregates one minute of audit events. Maps stay nil for minutes without such events.
type bucket struct {
	Minute     int64          `json:"m"`
	Requests   int            `json:"req"`
	Guarded    int            `json:"guarded,omitempty"`
	NewTurns   int            `json:"new_turns,omitempty"` // classifier calls (cache misses)
	CacheHits  int            `json:"cache_hits,omitempty"`
	WouldBlock int            `json:"would_block,omitempty"`
	Enforced   int            `json:"enforced,omitempty"`
	Status5xx  int            `json:"status_5xx,omitempty"`
	ClsErrors  int            `json:"cls_errors,omitempty"`
	Latency    []int          `json:"lat,omitempty"`
	Decisions  map[string]int `json:"decisions,omitempty"`
	Reasons    map[string]int `json:"reasons,omitempty"`
	Labels     map[string]int `json:"labels,omitempty"`
	Categories map[string]int `json:"categories,omitempty"`
	Protocols  map[string]int `json:"protocols,omitempty"`
}

// Stats keeps 7 days of per-minute aggregates and the latest guarded events (metadata only, the
// same fields as the audit line) so the console survives restarts without reading journald.
type Stats struct {
	mu      sync.Mutex
	buckets map[int64]*bucket
	dims    map[int64]*dimHour // per-hour groupings by key, client and model
	aliases map[string]Alias   // credential fingerprint -> admin label
	events  []audit.Event      // ring, oldest first once full
	next    int
	path    string
	now     func() time.Time
	// blockReply is the console's block-reply switch, kept here so it survives restarts.
	blockReply bool
	saveMu     sync.Mutex // orders whole saves so an older snapshot never replaces a newer one
}

type snapshot struct {
	Buckets    []*bucket        `json:"buckets"`
	Events     []audit.Event    `json:"events"`
	BlockReply bool             `json:"block_reply,omitempty"`
	Dims       []*dimHour       `json:"dims,omitempty"`
	Aliases    map[string]Alias `json:"aliases,omitempty"`
}

// NewStats loads path if it exists. An empty path keeps counters in memory only.
// A corrupt file is an error; the caller can fall back to volatile counters without overwriting it.
func NewStats(path string) (*Stats, error) {
	s := &Stats{buckets: map[int64]*bucket{}, dims: map[int64]*dimHour{}, aliases: map[string]Alias{}, path: path, now: time.Now}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields["buckets"] == nil || fields["events"] == nil {
		return nil, errors.New("invalid console statistics snapshot: buckets and events required")
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, err
	}
	oldest := s.now().Add(-retention).Unix() / 60
	for _, b := range snap.Buckets {
		if b == nil || len(b.Latency) > len(latencyBounds)+1 {
			return nil, errors.New("invalid console statistics bucket")
		}
		if b.Minute >= oldest {
			s.buckets[b.Minute] = b
		}
	}
	for _, dh := range snap.Dims {
		if dh == nil || dh.Dims == nil {
			return nil, errors.New("invalid console statistics dimensions")
		}
		if dh.Hour >= oldest/60 {
			s.dims[dh.Hour] = dh
		}
	}
	for k, a := range snap.Aliases {
		s.aliases[k] = a
	}
	for _, e := range snap.Events {
		s.addEvent(e)
	}
	s.blockReply = snap.BlockReply
	return s, nil
}

func (s *Stats) BlockReply() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blockReply
}

// SetBlockReply records the switch and saves immediately rather than on the next minute tick.
func (s *Stats) SetBlockReply(on bool) error {
	s.mu.Lock()
	s.blockReply = on
	s.mu.Unlock()
	return s.Save()
}

func inc(m *map[string]int, k string) {
	if k == "" {
		return
	}
	if *m == nil {
		*m = map[string]int{}
	}
	(*m)[k]++
}

func (s *Stats) Add(e audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	min := e.Timestamp.Unix() / 60
	b := s.buckets[min]
	if b == nil {
		b = &bucket{Minute: min}
		s.buckets[min] = b
	}
	b.Requests++
	if e.HTTPStatus >= 500 {
		b.Status5xx++
	}
	if e.Decision == "passthrough" {
		return
	}
	b.Guarded++
	s.addDims(e)
	inc(&b.Decisions, e.Decision)
	inc(&b.Reasons, e.ReasonCode)
	inc(&b.Protocols, e.Protocol)
	if e.WouldBlock {
		b.WouldBlock++
	}
	if e.Enforced {
		b.Enforced++
	}
	if e.ClassifierStatus != "" {
		inc(&b.Labels, e.Label)
		for _, c := range e.Categories {
			inc(&b.Categories, c)
		}
		switch {
		case e.CacheHit:
			b.CacheHits++
		case e.ClassifierStatus == "busy":
			// rejected by the local gate: no classifier call was made
			b.ClsErrors++
		default:
			b.NewTurns++
			if e.ClassifierStatus != "ok" {
				b.ClsErrors++
			}
			if b.Latency == nil {
				b.Latency = make([]int, len(latencyBounds)+1)
			}
			b.Latency[latencyBin(e.ClassifierMS)]++
		}
	}
	s.addEvent(e)
}

func latencyBin(ms int64) int {
	for i, ub := range latencyBounds {
		if ms <= ub {
			return i
		}
	}
	return len(latencyBounds)
}

func (s *Stats) addEvent(e audit.Event) {
	if len(s.events) < recentEvents {
		s.events = append(s.events, e)
		return
	}
	s.events[s.next] = e
	s.next = (s.next + 1) % recentEvents
}

// Save writes the snapshot atomically (0600) and drops expired minutes.
func (s *Stats) Save() error {
	if s.path == "" {
		return nil
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	oldest := s.now().Add(-retention).Unix() / 60
	snap := snapshot{Events: s.recent(), BlockReply: s.blockReply, Aliases: s.aliases}
	for m, b := range s.buckets {
		if m < oldest {
			delete(s.buckets, m)
			continue
		}
		snap.Buckets = append(snap.Buckets, b)
	}
	for h, dh := range s.dims {
		if h < oldest/60 {
			delete(s.dims, h)
			continue
		}
		snap.Dims = append(snap.Dims, dh)
	}
	raw, err := json.Marshal(snap)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".console-stats-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// recent returns the event ring oldest first; caller holds mu.
func (s *Stats) recent() []audit.Event {
	out := make([]audit.Event, 0, len(s.events))
	out = append(out, s.events[s.next:]...)
	return append(out, s.events[:s.next]...)
}

// Summary is the console's view of one time range.
type Summary struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	StepSeconds int       `json:"step_seconds"`
	Totals      bucket    `json:"totals"`
	Series      []bucket  `json:"series"`
	PeakTurns   int       `json:"peak_new_turns_per_minute"`
	LatencyP50  int64     `json:"latency_p50_ms"`
	LatencyP95  int64     `json:"latency_p95_ms"`
	LatencyP99  int64     `json:"latency_p99_ms"`
	Bounds      []int64   `json:"latency_bounds_ms"`
	TopReasons  []kv      `json:"top_reasons"`
	Categories  []kv      `json:"categories"`
}

type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func (s *Stats) Summary(window, step time.Duration) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	stepMin := int64(step / time.Minute)
	nowMin := s.now().Unix() / 60
	// Align so the last point is the current (partial) step.
	last := nowMin - nowMin%stepMin
	n := int64(window / step)
	first := last - (n-1)*stepMin
	sum := Summary{
		From: time.Unix(first*60, 0).UTC(), To: s.now().UTC(), StepSeconds: int(step / time.Second),
		Series: make([]bucket, n), Bounds: latencyBounds,
	}
	for i := range sum.Series {
		sum.Series[i].Minute = first + int64(i)*stepMin
	}
	for m, b := range s.buckets {
		if m < first || m >= last+stepMin {
			continue
		}
		if b.NewTurns > sum.PeakTurns {
			sum.PeakTurns = b.NewTurns
		}
		merge(&sum.Series[(m-first)/stepMin], b)
		merge(&sum.Totals, b)
	}
	sum.Totals.Minute = first
	for i := range sum.Series {
		// series points carry counters only; breakdowns are in totals
		sum.Series[i].Decisions, sum.Series[i].Reasons, sum.Series[i].Labels = nil, nil, nil
		sum.Series[i].Categories, sum.Series[i].Protocols, sum.Series[i].Latency = nil, nil, nil
	}
	sum.LatencyP50 = percentile(sum.Totals.Latency, .50)
	sum.LatencyP95 = percentile(sum.Totals.Latency, .95)
	sum.LatencyP99 = percentile(sum.Totals.Latency, .99)
	sum.TopReasons = sorted(sum.Totals.Reasons)
	sum.Categories = sorted(sum.Totals.Categories)
	return sum
}

func merge(dst, src *bucket) {
	dst.Requests += src.Requests
	dst.Guarded += src.Guarded
	dst.NewTurns += src.NewTurns
	dst.CacheHits += src.CacheHits
	dst.WouldBlock += src.WouldBlock
	dst.Enforced += src.Enforced
	dst.Status5xx += src.Status5xx
	dst.ClsErrors += src.ClsErrors
	if src.Latency != nil {
		if dst.Latency == nil {
			dst.Latency = make([]int, len(latencyBounds)+1)
		}
		for i, v := range src.Latency {
			dst.Latency[i] += v
		}
	}
	for _, p := range []struct{ d, s *map[string]int }{
		{&dst.Decisions, &src.Decisions}, {&dst.Reasons, &src.Reasons}, {&dst.Labels, &src.Labels},
		{&dst.Categories, &src.Categories}, {&dst.Protocols, &src.Protocols},
	} {
		for k, v := range *p.s {
			if *p.d == nil {
				*p.d = map[string]int{}
			}
			(*p.d)[k] += v
		}
	}
}

// percentile returns the upper bound of the histogram bin holding quantile q (-1 when open-ended,
// 0 when empty).
func percentile(h []int, q float64) int64 {
	total := 0
	for _, v := range h {
		total += v
	}
	if total == 0 {
		return 0
	}
	rank, seen := int(math.Ceil(q*float64(total))), 0 // nearest-rank
	for i, v := range h {
		seen += v
		if seen >= rank {
			if i == len(latencyBounds) {
				return -1
			}
			return latencyBounds[i]
		}
	}
	return -1
}

func sorted(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Events returns the latest guarded events, newest first.
func (s *Stats) Events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := s.recent()
	for i, j := 0, len(ev)-1; i < j; i, j = i+1, j-1 {
		ev[i], ev[j] = ev[j], ev[i]
	}
	return ev
}
