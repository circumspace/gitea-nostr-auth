package nostr

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"
)

const (
	// FetchTimeout bounds each phase (relay list, profile) of a lookup.
	FetchTimeout = 5 * time.Second
	// CacheTTL is how long to cache relay lists and profiles.
	CacheTTL = 24 * time.Hour
	// NegativeCacheTTL is how long to cache a failed lookup.
	NegativeCacheTTL = 5 * time.Minute

	maxCacheEntries     = 10000
	maxConcurrentDials  = 32
	maxMessageBytes     = 128 << 10
	maxEventsPerRelay   = 10
	maxProfileJSONBytes = 64 << 10
	maxRelayTags        = 100
)

// Options configure a Fetcher.
type Options struct {
	FallbackRelays []string
	// MaxUserRelays caps how many read relays from the NIP-65 list are used.
	MaxUserRelays int
	// AllowPrivate disables the non-public address guard (tests only).
	AllowPrivate bool
}

// Fetcher fetches relay lists and profiles from Nostr relays. Outbound
// connections go through a dialer that refuses non-public addresses, user
// supplied relays must be wss:// and are capped in number, and every event
// is checked for id, signature and filter match before use.
type Fetcher struct {
	fallbackRelays []string
	maxUserRelays  int
	// userRelayFilter validates relay URLs from NIP-65 lists (replaceable in tests).
	userRelayFilter func(string) string
	httpClient      *http.Client
	sem             chan struct{}
	relayCache      *ttlCache[[]Nip65Relay]
	profileCache    *ttlCache[*ProfileMetadata]
}

// NewFetcher creates a new Fetcher.
func NewFetcher(opts Options) *Fetcher {
	dialer := &net.Dialer{Timeout: FetchTimeout, KeepAlive: 30 * time.Second}
	if !opts.AllowPrivate {
		dialer.Control = guardControl
	}
	transport := &http.Transport{
		Proxy:                 nil, // never route through environment proxies: the guard must see the real peer
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   FetchTimeout,
		ResponseHeaderTimeout: FetchTimeout,
		MaxIdleConns:          0,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var fallback []string
	for _, r := range opts.FallbackRelays {
		if n := normalizeRelayURL(r, true); n != "" {
			fallback = append(fallback, n)
		} else {
			log.Printf("ignoring invalid fallback relay %q", r)
		}
	}
	return &Fetcher{
		fallbackRelays:  fallback,
		maxUserRelays:   opts.MaxUserRelays,
		userRelayFilter: func(u string) string { return normalizeRelayURL(u, false) },
		httpClient:      client,
		sem:             make(chan struct{}, maxConcurrentDials),
		relayCache:      newTTLCache[[]Nip65Relay](maxCacheEntries),
		profileCache:    newTTLCache[*ProfileMetadata](maxCacheEntries),
	}
}

func newPubkeyFilter(k int, pubkey string, limit int) gonostr.Filter {
	return gonostr.Filter{
		Kinds:   []int{k},
		Authors: []string{pubkey},
		Limit:   limit,
	}
}

// FetchRelayList fetches a user's NIP-65 relay list (kind 10002).
func (f *Fetcher) FetchRelayList(ctx context.Context, pubkey string) []Nip65Relay {
	if !IsHexPubkey(pubkey) {
		return nil
	}
	if relays, ok := f.relayCache.Get(pubkey); ok {
		return relays
	}
	relays, found := f.doFetchRelayList(ctx, pubkey)
	ttl := CacheTTL
	if !found {
		ttl = NegativeCacheTTL
	}
	f.relayCache.Set(pubkey, relays, ttl)
	return relays
}

func (f *Fetcher) doFetchRelayList(ctx context.Context, pubkey string) ([]Nip65Relay, bool) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	latest := latestEvent(f.queryRelays(ctx, f.fallbackRelays, newPubkeyFilter(10002, pubkey, maxEventsPerRelay)))
	if latest == nil {
		return nil, false
	}

	var relays []Nip65Relay
	for i, t := range latest.Tags {
		if i >= maxRelayTags {
			break
		}
		if len(t) < 2 || t[0] != "r" {
			continue
		}
		u := f.userRelayFilter(t[1])
		if u == "" {
			continue
		}
		relay := Nip65Relay{URL: u, Read: true, Write: true}
		if len(t) >= 3 {
			switch t[2] {
			case "read":
				relay.Write = false
			case "write":
				relay.Read = false
			}
		}
		relays = append(relays, relay)
	}
	return relays, true
}

// FetchProfile fetches a user's profile metadata (kind 0). It first fetches
// the user's relay list, then queries a capped number of the user's read
// relays plus the fallback relays.
func (f *Fetcher) FetchProfile(ctx context.Context, pubkey string) *ProfileMetadata {
	if !IsHexPubkey(pubkey) {
		return nil
	}
	if p, ok := f.profileCache.Get(pubkey); ok {
		return p
	}

	userRelays := f.FetchRelayList(ctx, pubkey)

	relayURLs := make([]string, 0, f.maxUserRelays+len(f.fallbackRelays))
	seen := make(map[string]bool)
	added := 0
	for _, r := range userRelays {
		if added >= f.maxUserRelays {
			break
		}
		if r.Read && !seen[r.URL] {
			relayURLs = append(relayURLs, r.URL)
			seen[r.URL] = true
			added++
		}
	}
	for _, u := range f.fallbackRelays {
		if !seen[u] {
			relayURLs = append(relayURLs, u)
			seen[u] = true
		}
	}

	profile := f.doFetchProfile(ctx, pubkey, relayURLs)
	ttl := CacheTTL
	if profile == nil {
		ttl = NegativeCacheTTL
	}
	f.profileCache.Set(pubkey, profile, ttl)
	return profile
}

func (f *Fetcher) doFetchProfile(ctx context.Context, pubkey string, relayURLs []string) *ProfileMetadata {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	latest := latestEvent(f.queryRelays(ctx, relayURLs, newPubkeyFilter(0, pubkey, maxEventsPerRelay)))
	if latest == nil {
		return nil
	}
	return parseProfile(pubkey, latest.Content)
}

func parseProfile(pubkey, content string) *ProfileMetadata {
	if len(content) > maxProfileJSONBytes {
		return nil
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(content), &c); err != nil {
		log.Printf("failed to parse profile content for %s: %v", TruncateNpub(PubkeyToNpub(pubkey)), err)
		return nil
	}
	str := func(k string) string {
		v, _ := c[k].(string)
		return v
	}
	p := &ProfileMetadata{
		Pubkey:      pubkey,
		Name:        SanitizeDisplayName(str("name")),
		DisplayName: SanitizeDisplayName(str("display_name")),
		Picture:     SafePictureURL(str("picture")),
		Nip05:       SanitizeDisplayName(str("nip05")),
	}
	if p.DisplayName == "" {
		p.DisplayName = SanitizeDisplayName(str("displayName"))
	}
	return p
}

func latestEvent(events []*gonostr.Event) *gonostr.Event {
	var latest *gonostr.Event
	for _, ev := range events {
		if latest == nil || ev.CreatedAt > latest.CreatedAt {
			latest = ev
		}
	}
	return latest
}

// queryRelays queries multiple relays concurrently and collects verified
// events matching ff.
func (f *Fetcher) queryRelays(ctx context.Context, relayURLs []string, ff gonostr.Filter) []*gonostr.Event {
	var (
		events   []*gonostr.Event
		eventsMu sync.Mutex
		wg       sync.WaitGroup
	)
	for _, u := range relayURLs {
		wg.Add(1)
		go func(relayURL string) {
			defer wg.Done()
			select {
			case f.sem <- struct{}{}:
				defer func() { <-f.sem }()
			case <-ctx.Done():
				return
			}
			evs, err := f.queryRelay(ctx, relayURL, ff)
			if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				log.Printf("relay %s: %v", relayURL, err)
			}
			eventsMu.Lock()
			events = append(events, evs...)
			eventsMu.Unlock()
		}(u)
	}
	wg.Wait()
	return events
}

const subID = "p"

func (f *Fetcher) queryRelay(ctx context.Context, relayURL string, ff gonostr.Filter) ([]*gonostr.Event, error) {
	conn, resp, err := websocket.Dial(ctx, relayURL, &websocket.DialOptions{
		HTTPClient: f.httpClient,
		HTTPHeader: http.Header{"User-Agent": {"gitea-nostr-auth"}},
	})
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxMessageBytes)

	req, err := gonostr.ReqEnvelope{SubscriptionID: subID, Filters: gonostr.Filters{ff}}.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := conn.Write(ctx, websocket.MessageText, req); err != nil {
		return nil, err
	}

	var events []*gonostr.Event
	for len(events) < maxEventsPerRelay {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return events, err
		}
		var msg []json.RawMessage
		if err := json.Unmarshal(data, &msg); err != nil || len(msg) < 2 {
			continue
		}
		var label, sid string
		if json.Unmarshal(msg[0], &label) != nil {
			continue
		}
		_ = json.Unmarshal(msg[1], &sid)
		switch label {
		case "EVENT":
			if sid != subID || len(msg) < 3 {
				continue
			}
			var ev gonostr.Event
			if err := json.Unmarshal(msg[2], &ev); err != nil {
				continue
			}
			if ValidEvent(&ev) && ff.Matches(&ev) {
				events = append(events, &ev)
			}
		case "EOSE", "CLOSED":
			if sid == subID {
				closeMsg, _ := json.Marshal([]string{"CLOSE", subID})
				_ = conn.Write(ctx, websocket.MessageText, closeMsg)
				conn.Close(websocket.StatusNormalClosure, "")
				return events, nil
			}
		}
	}
	return events, nil
}

// ValidEvent reports whether the event id is the hash of its canonical
// serialisation and the signature over that hash is valid for its pubkey.
func ValidEvent(ev *gonostr.Event) bool {
	if !IsHexPubkey(ev.PubKey) || !ev.CheckID() {
		return false
	}
	ok, err := ev.CheckSignature()
	return err == nil && ok
}
