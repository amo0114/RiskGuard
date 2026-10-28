// Package limits holds pre-auth resource budgets for the classifier. They protect the remote
// classifier and this host; they are not user rate limits (New API owns those).
package limits

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrBusy    = errors.New("queue full")
	ErrTimeout = errors.New("queue wait timeout")
)

// Gate allows max concurrent holders and at most maxQueue waiters.
type Gate struct {
	slots   chan struct{}
	waiting chan struct{}
}

func NewGate(max, maxQueue int) *Gate {
	return &Gate{slots: make(chan struct{}, max), waiting: make(chan struct{}, maxQueue)}
}

// Acquire waits up to wait for a slot. The returned release must be called exactly once.
func (g *Gate) Acquire(ctx context.Context, wait time.Duration) (func(), error) {
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	default:
	}
	select {
	case g.waiting <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	defer func() { <-g.waiting }()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	case <-t.C:
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *Gate) release() { <-g.slots }

// InUse returns current holders and waiters.
func (g *Gate) InUse() (int, int) { return len(g.slots), len(g.waiting) }

// KeyedRate is a per-key token bucket (perMinute tokens, burst = perMinute). Idle keys are evicted;
// when maxKeys distinct keys are live, unseen keys share one overflow bucket instead of growing
// the map.
type KeyedRate struct {
	mu        sync.Mutex
	perMinute float64
	maxKeys   int
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const overflowKey = "\x00overflow"

func NewKeyedRate(perMinute, maxKeys int) *KeyedRate {
	return &KeyedRate{perMinute: float64(perMinute), maxKeys: maxKeys, buckets: map[string]*bucket{}, now: time.Now}
}

func (k *KeyedRate) Allow(key string) bool {
	if k.perMinute <= 0 {
		return true
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if now.Sub(k.lastSweep) > time.Minute {
		for key, b := range k.buckets {
			if now.Sub(b.last) > 2*time.Minute {
				delete(k.buckets, key)
			}
		}
		k.lastSweep = now
	}
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			key = overflowKey
			b = k.buckets[key]
		}
		if b == nil {
			b = &bucket{tokens: k.perMinute, last: now}
			k.buckets[key] = b
		}
	}
	b.tokens += now.Sub(b.last).Minutes() * k.perMinute
	if b.tokens > k.perMinute {
		b.tokens = k.perMinute
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
