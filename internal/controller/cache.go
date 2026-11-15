package controller

import (
	"context"
	"sync"
	"time"
)

// Conn is a client of a provider the cache keeps: *idpclient.Keycloak or
// *idpclient.DCR. Closing it is closing its idle connections.
type Conn interface {
	CloseIdleConnections()
}

// ProviderCache keeps one client per provider between reconciles, so the
// operator keeps its Keycloak admin token and its connections instead of
// starting over for every reconcile. An entry is valid for one version, the
// stamp: the provider object (its UID and generation) and everything its client
// is made from (credentials, CA, proxy), so it is replaced as soon as any of
// them changes.
//
// Get hands out a lease: the client and a release function. A replaced or
// forgotten entry is only marked stale; its connections are closed when the last
// lease on it is released, so a reconcile never loses the client it uses. An
// entry nobody holds a lease on and nobody used for the idle time is closed by
// the next Get or by the sweep that Start runs. A nil *ProviderCache caches
// nothing: its leases close the client on release.
type ProviderCache struct {
	mu      sync.Mutex
	idle    time.Duration
	now     func() time.Time
	tick    func(time.Duration) (<-chan time.Time, func())
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	version string
	conn    Conn
	used    time.Time
	leases  int
	stale   bool
}

// NewProviderCache returns a cache that closes an entry nobody used for longer
// than idle.
func NewProviderCache(idle time.Duration) *ProviderCache {
	return &ProviderCache{idle: idle, now: time.Now, tick: newTicker, entries: map[string]*cacheEntry{}}
}

func newTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Get returns a lease on the client cached for key if it was made for version,
// else builds one, replaces the entry and retires the old client. The caller
// calls the release function once it is done with the client, and not before. A
// failed build caches nothing. build runs with the lock held: a provider that
// does not answer holds up the other providers' reconciles, which is the price
// of a cache without a second lock (building a client makes no request, so it
// does not wait on the network).
func (c *ProviderCache) Get(key, version string, build func() (Conn, error)) (Conn, func(), error) {
	if c == nil {
		b, err := build()
		if err != nil {
			return nil, nil, err
		}
		return b, b.CloseIdleConnections, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweep(now)
	if e, ok := c.entries[key]; ok && e.version == version {
		return c.lease(e, now)
	}
	c.retire(key)
	b, err := build()
	if err != nil {
		return nil, nil, err
	}
	e := &cacheEntry{version: version, conn: b, used: now}
	c.entries[key] = e
	return c.lease(e, now)
}

// lease counts a new holder of e. The caller holds mu.
func (c *ProviderCache) lease(e *cacheEntry, now time.Time) (Conn, func(), error) {
	e.leases++
	e.used = now
	released := false
	return e.conn, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			return
		}
		released = true
		e.leases--
		e.used = c.now()
		if e.stale && e.leases == 0 {
			e.conn.CloseIdleConnections()
		}
	}, nil
}

// Forget retires the entry of a provider that no longer exists.
func (c *ProviderCache) Forget(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retire(key)
}

// Len is the number of cached providers.
func (c *ProviderCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// retire removes an entry from the cache. Its connections are closed now when
// nobody holds a lease on it, else by the release of the last lease. The caller
// holds mu.
func (c *ProviderCache) retire(key string) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	e.stale = true
	if e.leases == 0 {
		e.conn.CloseIdleConnections()
	}
}

// sweep retires the entries nobody holds a lease on and nobody used for longer
// than the idle time. The caller holds mu.
func (c *ProviderCache) sweep(now time.Time) {
	for k, e := range c.entries {
		if e.leases == 0 && now.Sub(e.used) > c.idle {
			c.retire(k)
		}
	}
}

// Start implements manager.Runnable: it sweeps the idle entries every half idle
// period, so the connections to a provider nobody reconciles any more are
// closed without waiting for a Get. It returns when ctx is cancelled, and
// closes what is left once nobody holds it.
func (c *ProviderCache) Start(ctx context.Context) error {
	ticks, stop := c.tick(max(c.idle/2, time.Second))
	defer stop()
	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			for k := range c.entries {
				c.retire(k)
			}
			c.mu.Unlock()
			return nil
		case <-ticks:
			c.mu.Lock()
			c.sweep(c.now())
			c.mu.Unlock()
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every replica
// closes its own idle connections.
func (c *ProviderCache) NeedLeaderElection() bool { return false }
