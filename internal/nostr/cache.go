package nostr

import (
	"sync"
	"time"
)

// ttlCache is a small size-bounded cache with per-entry expiry.
type ttlCache[V any] struct {
	mu      sync.Mutex
	max     int
	entries map[string]ttlEntry[V]
}

type ttlEntry[V any] struct {
	val V
	exp time.Time
}

func newTTLCache[V any](max int) *ttlCache[V] {
	return &ttlCache[V]{max: max, entries: make(map[string]ttlEntry[V])}
}

func (c *ttlCache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.exp) {
		var zero V
		return zero, false
	}
	return e.val, true
}

func (c *ttlCache[V]) Set(key string, val V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.max {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.exp) {
				delete(c.entries, k)
			}
		}
		// Still full: evict arbitrary entries (map order is random).
		for k := range c.entries {
			if len(c.entries) < c.max {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = ttlEntry[V]{val: val, exp: time.Now().Add(ttl)}
}

func (c *ttlCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
