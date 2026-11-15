package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errBuild = errors.New("build failed")

// memConn counts how often it was closed.
type memConn struct {
	mu     sync.Mutex
	closed int
	// inUse and closedInUse catch a close while a reconcile holds the client.
	inUse       atomic.Int32
	closedInUse atomic.Bool
}

func (m *memConn) CloseIdleConnections() {
	if m.inUse.Load() > 0 {
		m.closedInUse.Store(true)
	}
	m.mu.Lock()
	m.closed++
	m.mu.Unlock()
}

func (m *memConn) closes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func buildMem() (Conn, error) { return &memConn{}, nil }

func TestProviderCache(t *testing.T) {
	c := NewProviderCache(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	builds := 0
	build := func() (Conn, error) { builds++; return &memConn{}, nil }
	// get takes a lease and gives it back at once, as a reconcile that is over.
	get := func(key, version string) *memConn {
		v, release, err := c.Get(key, version, build)
		if err != nil {
			t.Fatal(err)
		}
		release()
		return v.(*memConn)
	}

	v1 := get("k", "v1")
	if again := get("k", "v1"); again != v1 || builds != 1 {
		t.Errorf("a hit built a new client (builds = %d)", builds)
	}

	// A new stamp replaces the entry and closes the old client.
	v2 := get("k", "v2")
	if v2 == v1 || builds != 2 || v1.closes() != 1 {
		t.Errorf("invalidation: builds = %d, closed = %d", builds, v1.closes())
	}

	// A failed build caches nothing and keeps no stale entry.
	if _, _, err := c.Get("bad", "v", func() (Conn, error) { return nil, errBuild }); !errors.Is(err, errBuild) || c.Len() != 1 {
		t.Errorf("failed build: %v, len = %d", err, c.Len())
	}
	if _, _, err := c.Get("k", "v3", func() (Conn, error) { return nil, errBuild }); !errors.Is(err, errBuild) || c.Len() != 0 {
		t.Errorf("failed rebuild: %v, len = %d", err, c.Len())
	}

	// Removal: the provider is gone.
	v4 := get("gone", "v")
	c.Forget("gone")
	c.Forget("gone")
	if c.Len() != 0 || v4.closes() != 1 {
		t.Errorf("Forget: len = %d, closed = %d", c.Len(), v4.closes())
	}

	// An entry that is not used for longer than the idle time is dropped by the
	// next Get, whatever its key.
	v5 := get("old", "v")
	now = now.Add(30 * time.Second)
	get("young", "v")
	now = now.Add(45 * time.Second)
	get("young", "v")
	if c.Len() != 1 || v5.closes() != 1 {
		t.Errorf("idle: len = %d, closed = %d", c.Len(), v5.closes())
	}
}

// A client that is replaced, forgotten or idle while a reconcile holds a lease
// on it stays open until the lease is released.
func TestProviderCacheClosesAfterTheLastLease(t *testing.T) {
	c := NewProviderCache(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }

	v1, rel1, _ := c.Get("k", "v1", buildMem)
	v1again, rel1b, _ := c.Get("k", "v1", buildMem)
	if v1again != v1 {
		t.Fatal("a hit built a new client")
	}
	// Replaced while two leases are out.
	v2, rel2, _ := c.Get("k", "v2", buildMem)
	if v2 == v1 || v1.(*memConn).closes() != 0 {
		t.Fatalf("a replaced client in use was closed (%d)", v1.(*memConn).closes())
	}
	rel1()
	rel1() // releasing twice counts once
	if v1.(*memConn).closes() != 0 {
		t.Fatal("closed while the second lease is out")
	}
	rel1b()
	if v1.(*memConn).closes() != 1 {
		t.Fatalf("closed = %d after the last release", v1.(*memConn).closes())
	}

	// Forgotten while leased.
	c.Forget("k")
	if c.Len() != 0 || v2.(*memConn).closes() != 0 {
		t.Fatalf("Forget closed a client in use (len %d)", c.Len())
	}
	rel2()
	if v2.(*memConn).closes() != 1 {
		t.Fatal("not closed after its last release")
	}

	// A leased entry is never idle; it is once released and left alone.
	v3, rel3, _ := c.Get("i", "v", buildMem)
	now = now.Add(time.Hour)
	_, relX, _ := c.Get("other", "v", buildMem)
	relX()
	if c.Len() != 2 || v3.(*memConn).closes() != 0 {
		t.Fatalf("an entry in use was swept (len %d)", c.Len())
	}
	rel3()
	now = now.Add(2 * time.Minute)
	c.mu.Lock()
	c.sweep(c.now())
	c.mu.Unlock()
	if c.Len() != 0 || v3.(*memConn).closes() != 1 {
		t.Fatalf("idle entries stayed (len %d)", c.Len())
	}
}

// Many reconciles that get, use, replace and forget clients at once never have
// one closed under them (run with the race detector).
func TestProviderCacheNeverClosesAClientInUse(t *testing.T) {
	c := NewProviderCache(time.Millisecond)
	var mu sync.Mutex
	var all []*memConn
	build := func() (Conn, error) {
		m := &memConn{}
		mu.Lock()
		all = append(all, m)
		mu.Unlock()
		return m, nil
	}
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				v, release, err := c.Get("k", fmt.Sprintf("v%d", (i+w)%3), build)
				if err != nil {
					t.Error(err)
					return
				}
				m := v.(*memConn)
				m.inUse.Add(1)
				if i%17 == 0 {
					c.Forget("k")
				}
				time.Sleep(time.Microsecond)
				m.inUse.Add(-1)
				release()
			}
		}()
	}
	wg.Wait()
	for _, m := range all {
		if m.closedInUse.Load() {
			t.Fatal("a client was closed while a reconcile used it")
		}
	}
	c.Forget("k")
	for _, m := range all {
		if n := m.closes(); n != 1 {
			t.Fatalf("a client was closed %d times", n)
		}
	}
}

// Start closes idle, unleased entries on its interval without a Get, and stops
// when its context is cancelled.
func TestProviderCacheSweeper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := NewProviderCache(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	ticks := make(chan time.Time)
	var interval time.Duration
	stopped := make(chan struct{})
	c.tick = func(d time.Duration) (<-chan time.Time, func()) {
		interval = d
		return ticks, func() { close(stopped) }
	}
	if c.NeedLeaderElection() {
		t.Error("the sweeper needs no leader")
	}
	v, release, _ := c.Get("k", "v", buildMem)
	held, relHeld, _ := c.Get("held", "v", buildMem)
	release()

	done := make(chan error)
	go func() { done <- c.Start(ctx) }()
	now = now.Add(time.Hour)
	ticks <- now
	ticks <- now // taken only when the sweep of the first tick is over
	if c.Len() != 1 || v.(*memConn).closes() != 1 || held.(*memConn).closes() != 0 {
		t.Errorf("sweep: len = %d, closed = %d, held closed = %d", c.Len(), v.(*memConn).closes(), held.(*memConn).closes())
	}
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
	<-stopped
	if c.Len() != 0 || held.(*memConn).closes() != 0 {
		t.Errorf("shutdown: len = %d, held closed = %d (a leased client stays open)", c.Len(), held.(*memConn).closes())
	}
	relHeld()
	if held.(*memConn).closes() != 1 {
		t.Errorf("held closed = %d after its release", held.(*memConn).closes())
	}
	if interval != 30*time.Second {
		t.Errorf("interval = %v", interval)
	}
}

func TestNewTicker(t *testing.T) {
	ch, stop := newTicker(time.Millisecond)
	defer stop()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no tick")
	}
}

// A nil cache caches nothing, and has nothing to count.
func TestNilProviderCacheCachesNothing(t *testing.T) {
	var c *ProviderCache
	var made []*memConn
	for range 2 {
		_, release, err := c.Get("k", "v", func() (Conn, error) {
			m := &memConn{}
			made = append(made, m)
			return m, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if _, _, err := c.Get("k", "v", func() (Conn, error) { return nil, errBuild }); !errors.Is(err, errBuild) {
		t.Errorf("err = %v", err)
	}
	c.Forget("k")
	if c.Len() != 0 || len(made) != 2 || made[0].closes() != 1 || made[1].closes() != 1 {
		t.Errorf("made = %d, a release must close the client", len(made))
	}
}
