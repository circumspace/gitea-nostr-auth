package nostr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"
)

// fakeRelay answers every REQ with the given events (in order) and EOSE.
type fakeRelay struct {
	events []gonostr.Event
	hits   atomic.Int32
}

func (fr *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fr.hits.Add(1)
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var msg []json.RawMessage
		if json.Unmarshal(data, &msg) != nil || len(msg) < 2 {
			continue
		}
		var label, sid string
		_ = json.Unmarshal(msg[0], &label)
		_ = json.Unmarshal(msg[1], &sid)
		if label != "REQ" {
			continue
		}
		for _, ev := range fr.events {
			b, _ := json.Marshal([]any{"EVENT", sid, ev})
			_ = c.Write(ctx, websocket.MessageText, b)
		}
		b, _ := json.Marshal([]any{"EOSE", sid})
		_ = c.Write(ctx, websocket.MessageText, b)
	}
}

func wsURL(s *httptest.Server) string { return "ws" + strings.TrimPrefix(s.URL, "http") + "/" }

func signed(t *testing.T, sk string, kind int, content string, tags gonostr.Tags, at time.Time) gonostr.Event {
	t.Helper()
	ev := gonostr.Event{Kind: kind, Content: content, Tags: tags, CreatedAt: gonostr.Timestamp(at.Unix())}
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestFetchProfileVerifiesEvents(t *testing.T) {
	sk := gonostr.GeneratePrivateKey()
	pk, _ := gonostr.GetPublicKey(sk)
	other := gonostr.GeneratePrivateKey()
	now := time.Now()

	good := signed(t, sk, 0, `{"name":"alice","picture":"https://example.com/a.png","nip05":"admin@example.com"}`, nil, now.Add(-time.Hour))

	// Newer but forged: content swapped after signing (id no longer matches).
	forged := signed(t, sk, 0, `{"name":"x"}`, nil, now)
	forged.Content = `{"name":"admin"}`
	// Newer, validly signed but by another key with pubkey rewritten.
	wrongKey := signed(t, other, 0, `{"name":"mallory"}`, nil, now)
	wrongKey.PubKey = pk
	// Newer, by a different author (filter mismatch).
	otherAuthor := signed(t, other, 0, `{"name":"eve"}`, nil, now)
	// C-1 style: valid (id, sig) from another event pasted onto new content.
	note := signed(t, sk, 1, "gm", nil, now.Add(-48*time.Hour))
	pasted := gonostr.Event{ID: note.ID, Sig: note.Sig, PubKey: pk, Kind: 0, Content: `{"name":"root"}`, CreatedAt: gonostr.Timestamp(now.Unix())}

	relay := &fakeRelay{events: []gonostr.Event{good, forged, wrongKey, otherAuthor, pasted}}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	f := NewFetcher(Options{FallbackRelays: []string{wsURL(srv)}, MaxUserRelays: 5, AllowPrivate: true})
	p := f.FetchProfile(context.Background(), pk)
	if p == nil {
		t.Fatal("no profile")
	}
	if p.Name != "alice" {
		t.Fatalf("profile name %q: a forged or foreign event was accepted", p.Name)
	}
	if p.Picture != "https://example.com/a.png" {
		t.Fatalf("picture %q", p.Picture)
	}
}

func TestSSRFGuardBlocksLoopback(t *testing.T) {
	sk := gonostr.GeneratePrivateKey()
	pk, _ := gonostr.GetPublicKey(sk)
	relay := &fakeRelay{events: []gonostr.Event{signed(t, sk, 0, `{"name":"alice"}`, nil, time.Now())}}
	srv := httptest.NewServer(relay)
	defer srv.Close()

	f := NewFetcher(Options{FallbackRelays: []string{wsURL(srv)}, MaxUserRelays: 5})
	if p := f.FetchProfile(context.Background(), pk); p != nil {
		t.Fatal("profile fetched from loopback relay despite SSRF guard")
	}
	if relay.hits.Load() != 0 {
		t.Fatalf("guarded fetcher connected to loopback %d times", relay.hits.Load())
	}
}

func TestUserRelayListCappedAndFiltered(t *testing.T) {
	sk := gonostr.GeneratePrivateKey()
	pk, _ := gonostr.GetPublicKey(sk)

	userRelay := &fakeRelay{events: []gonostr.Event{signed(t, sk, 0, `{"name":"from-user-relay"}`, nil, time.Now())}}
	userSrv := httptest.NewServer(userRelay)
	defer userSrv.Close()

	tags := gonostr.Tags{
		{"r", "ws://10.0.0.1:6443/"},
		{"r", "wss://kubernetes.default.svc/"},
		{"r", "http://example.com/"},
		{"r", wsURL(userSrv), "write"}, // write-only: must not be queried for reading
	}
	for i := 0; i < 50; i++ {
		tags = append(tags, gonostr.Tag{"r", wsURL(userSrv)})
	}
	relayList := signed(t, sk, 10002, "", tags, time.Now())
	fallback := &fakeRelay{events: []gonostr.Event{relayList}}
	fbSrv := httptest.NewServer(fallback)
	defer fbSrv.Close()

	f := NewFetcher(Options{FallbackRelays: []string{wsURL(fbSrv)}, MaxUserRelays: 2, AllowPrivate: true})
	// Test relays are plain ws on loopback; allow exactly that one URL and
	// keep the production filter for everything else.
	f.userRelayFilter = func(u string) string {
		if u == wsURL(userSrv) {
			return u
		}
		return normalizeRelayURL(u, false)
	}
	relays := f.FetchRelayList(context.Background(), pk)
	for _, r := range relays {
		if strings.Contains(r.URL, "10.0.0.1") || strings.Contains(r.URL, ".svc") || strings.HasPrefix(r.URL, "http") {
			t.Errorf("unsafe relay kept: %s", r.URL)
		}
	}
	p := f.FetchProfile(context.Background(), pk)
	if p == nil || p.Name != "from-user-relay" {
		t.Fatalf("expected profile from user relay, got %+v", p)
	}
	// Duplicates are de-duplicated, so the user relay is dialled once per phase.
	if hits := userRelay.hits.Load(); hits != 1 {
		t.Fatalf("user relay dialled %d times, want 1", hits)
	}
}

func TestCacheBounded(t *testing.T) {
	c := newTTLCache[int](3)
	for i := 0; i < 10; i++ {
		c.Set(string(rune('a'+i)), i, time.Minute)
	}
	if c.Len() > 3 {
		t.Fatalf("cache grew to %d", c.Len())
	}
	c.Set("x", 1, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get("x"); ok {
		t.Fatal("expired entry returned")
	}
}
