package limits

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGate(t *testing.T) {
	g := NewGate(2, 1)
	r1, _ := g.Acquire(context.Background(), time.Second)
	r2, _ := g.Acquire(context.Background(), time.Second)
	done := make(chan error)
	go func() { // third waits in the single queue slot
		r, err := g.Acquire(context.Background(), 2*time.Second)
		if err == nil {
			r()
		}
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := g.Acquire(context.Background(), time.Second); !errors.Is(err, ErrBusy) {
		t.Fatalf("fourth should be rejected immediately, got %v", err)
	}
	r1()
	if err := <-done; err != nil {
		t.Fatalf("queued waiter: %v", err)
	}
	if _, err := g.Acquire(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("slot freed by waiter: %v", err)
	}
	if _, err := g.Acquire(context.Background(), 50*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected timeout, got %v", err)
	}
	r2()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g2 := NewGate(1, 1)
	rel, _ := g2.Acquire(context.Background(), time.Second)
	if _, err := g2.Acquire(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx: %v", err)
	}
	rel()
	if in, w := g2.InUse(); in != 0 || w != 0 {
		t.Fatalf("leak: %d %d", in, w)
	}
}

func TestKeyedRate(t *testing.T) {
	now := time.Unix(0, 0)
	k := NewKeyedRate(3, 2)
	k.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !k.Allow("a") {
			t.Fatal("burst denied")
		}
	}
	if k.Allow("a") {
		t.Fatal("4th allowed")
	}
	if !k.Allow("b") {
		t.Fatal("other key affected")
	}
	now = now.Add(20 * time.Second) // +1 token
	if !k.Allow("a") || k.Allow("a") {
		t.Fatal("refill wrong")
	}
	// map is full (a, b): new keys share the overflow bucket
	for i := 0; i < 3; i++ {
		k.Allow("new-" + string(rune('x'+i)))
	}
	if k.Allow("new-z") {
		t.Fatal("overflow bucket not shared")
	}
	now = now.Add(5 * time.Minute) // sweep evicts idle keys
	k.Allow("c")
	if len(k.buckets) > 2 {
		t.Fatalf("idle keys not evicted: %d", len(k.buckets))
	}
}
