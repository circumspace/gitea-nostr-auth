package nostr

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
)

const (
	// FetchTimeout is how long to wait for relay responses
	FetchTimeout = 10 * time.Second
	// CacheTTL is how long to cache relay lists and profiles
	CacheTTL = 24 * time.Hour
)

// Fetcher handles fetching relay lists and profiles from Nostr relays
type Fetcher struct {
	fallbackRelays []string
	relayCache     map[string]*relayListCacheEntry
	profileCache   map[string]*profileCacheEntry
	mu             sync.RWMutex
}

type relayListCacheEntry struct {
	Relays    []Nip65Relay
	FetchedAt time.Time
}

type profileCacheEntry struct {
	Profile   *ProfileMetadata
	FetchedAt time.Time
}

// NewFetcher creates a new Fetcher with the given fallback relays
func NewFetcher(fallbackRelays []string) *Fetcher {
	return &Fetcher{
		fallbackRelays: fallbackRelays,
		relayCache:     make(map[string]*relayListCacheEntry),
		profileCache:   make(map[string]*profileCacheEntry),
	}
}

// newPubkeyFilter builds a filter for a given kind and hex pubkey with a limit.
func newPubkeyFilter(k int, pubkey string, limit int) *gonostr.Filter {
	if !gonostr.IsValidPublicKey(pubkey) {
		return nil
	}
	return &gonostr.Filter{
		Kinds:   []int{k},
		Authors: []string{pubkey},
		Limit:   limit,
	}
}

// FetchRelayList fetches a user's NIP-65 relay list (kind 10002)
func (f *Fetcher) FetchRelayList(ctx context.Context, pubkey string) []Nip65Relay {
	// Check cache first
	f.mu.RLock()
	if entry, ok := f.relayCache[pubkey]; ok {
		if time.Since(entry.FetchedAt) < CacheTTL {
			f.mu.RUnlock()
			return entry.Relays
		}
	}
	f.mu.RUnlock()

	// Fetch from relays
	relays := f.doFetchRelayList(ctx, pubkey)

	// Cache result
	f.mu.Lock()
	f.relayCache[pubkey] = &relayListCacheEntry{
		Relays:    relays,
		FetchedAt: time.Now(),
	}
	f.mu.Unlock()

	return relays
}

func (f *Fetcher) doFetchRelayList(ctx context.Context, pubkey string) []Nip65Relay {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	ff := newPubkeyFilter(10002, pubkey, 10)
	if ff == nil {
		return nil
	}

	events := f.queryRelays(ctx, f.fallbackRelays, ff)
	if len(events) == 0 {
		return nil
	}

	// Get the most recent event
	var latest *gonostr.Event
	for _, ev := range events {
		if latest == nil || ev.CreatedAt > latest.CreatedAt {
			latest = ev
		}
	}

	// Parse relay tags
	var relays []Nip65Relay
	{
		for _, ss := range latest.Tags {
			if len(ss) >= 2 && ss[0] == "r" {
				relay := Nip65Relay{
					URL:   ss[1],
					Read:  true,
					Write: true,
				}
				if len(ss) >= 3 {
					switch ss[2] {
					case "read":
						relay.Write = false
					case "write":
						relay.Read = false
					}
				}
				relays = append(relays, relay)
			}
		}
	}

	return relays
}

// FetchProfile fetches a user's profile metadata (kind 0)
// It first fetches the user's relay list, then queries those relays + fallbacks
func (f *Fetcher) FetchProfile(ctx context.Context, pubkey string) *ProfileMetadata {
	// Check cache first
	f.mu.RLock()
	if entry, ok := f.profileCache[pubkey]; ok {
		if time.Since(entry.FetchedAt) < CacheTTL {
			f.mu.RUnlock()
			return entry.Profile
		}
	}
	f.mu.RUnlock()

	// First, get the user's relay list
	userRelays := f.FetchRelayList(ctx, pubkey)

	// Build relay list: user's read relays + fallbacks
	relayURLs := make([]string, 0, len(userRelays)+len(f.fallbackRelays))
	seen := make(map[string]bool)

	// Add user's read relays first (more likely to have their profile)
	for _, r := range userRelays {
		if r.Read && !seen[r.URL] {
			relayURLs = append(relayURLs, r.URL)
			seen[r.URL] = true
		}
	}

	// Add fallback relays
	for _, url := range f.fallbackRelays {
		if !seen[url] {
			relayURLs = append(relayURLs, url)
			seen[url] = true
		}
	}

	// Fetch profile
	profile := f.doFetchProfile(ctx, pubkey, relayURLs)

	// Cache result (even if nil)
	f.mu.Lock()
	f.profileCache[pubkey] = &profileCacheEntry{
		Profile:   profile,
		FetchedAt: time.Now(),
	}
	f.mu.Unlock()

	return profile
}

func (f *Fetcher) doFetchProfile(ctx context.Context, pubkey string, relayURLs []string) *ProfileMetadata {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	ff := newPubkeyFilter(0, pubkey, 10)
	if ff == nil {
		return nil
	}

	events := f.queryRelays(ctx, relayURLs, ff)
	if len(events) == 0 {
		return nil
	}

	// Get the most recent event
	var latest *gonostr.Event
	for _, ev := range events {
		if latest == nil || ev.CreatedAt > latest.CreatedAt {
			latest = ev
		}
	}

	// Parse profile content
	var content map[string]interface{}
	if err := json.Unmarshal([]byte(latest.Content), &content); err != nil {
		log.Printf("Failed to parse profile content for %s: %v", pubkey, err)
		return nil
	}

	profile := &ProfileMetadata{
		Pubkey: pubkey,
	}

	if v, ok := content["name"].(string); ok {
		profile.Name = v
	}
	if v, ok := content["display_name"].(string); ok {
		profile.DisplayName = v
	}
	if v, ok := content["displayName"].(string); ok && profile.DisplayName == "" {
		profile.DisplayName = v
	}
	if v, ok := content["picture"].(string); ok {
		profile.Picture = v
	}
	if v, ok := content["banner"].(string); ok {
		profile.Banner = v
	}
	if v, ok := content["about"].(string); ok {
		profile.About = v
	}
	if v, ok := content["website"].(string); ok {
		profile.Website = v
	}
	if v, ok := content["nip05"].(string); ok {
		profile.Nip05 = v
	}
	if v, ok := content["lud06"].(string); ok {
		profile.Lud06 = v
	}
	if v, ok := content["lud16"].(string); ok {
		profile.Lud16 = v
	}

	return profile
}

// queryRelays queries multiple relays and collects events
func (f *Fetcher) queryRelays(ctx context.Context, relayURLs []string, ff *gonostr.Filter) []*gonostr.Event {
	var (
		events   []*gonostr.Event
		eventsMu sync.Mutex
		wg       sync.WaitGroup
	)

	// Query each relay concurrently
	for _, url := range relayURLs {
		wg.Add(1)
		go func(relayURL string) {
			defer wg.Done()

			relay, err := gonostr.RelayConnect(ctx, relayURL)
			if err != nil {
				// Silently skip failed relays
				return
			}
			defer relay.Close()

			sub, err := relay.Subscribe(ctx, gonostr.Filters{*ff})
			if err != nil {
				return
			}
			defer sub.Unsub()

			for {
				select {
				case ev, ok := <-sub.Events:
					if !ok {
						return
					}
					eventsMu.Lock()
					events = append(events, ev)
					eventsMu.Unlock()
				case <-sub.EndOfStoredEvents:
					return
				case <-ctx.Done():
					return
				}
			}
		}(url)
	}

	// Wait for all queries to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	return events
}

// GetCachedProfile returns a cached profile if available and not expired
func (f *Fetcher) GetCachedProfile(pubkey string) *ProfileMetadata {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if entry, ok := f.profileCache[pubkey]; ok {
		if time.Since(entry.FetchedAt) < CacheTTL {
			return entry.Profile
		}
	}
	return nil
}

// GetCachedRelayList returns a cached relay list if available and not expired
func (f *Fetcher) GetCachedRelayList(pubkey string) []Nip65Relay {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if entry, ok := f.relayCache[pubkey]; ok {
		if time.Since(entry.FetchedAt) < CacheTTL {
			return entry.Relays
		}
	}
	return nil
}
