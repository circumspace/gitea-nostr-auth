package nip46

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/circumspace/gitea-nostr-auth/internal/nip46/nip46test"
)

var testTemplate = gonostr.Event{
	Kind:    27235,
	Tags:    gonostr.Tags{{"u", "https://auth.example.com/verify"}, {"method", "POST"}, {"challenge", "c1"}},
	Content: "Sign in to git.example.com via auth.example.com",
}

func newManager(t *testing.T, relay string, mutate ...func(*Options)) *Manager {
	opts := Options{Relay: relay, AllowPrivate: true, AppName: "auth.example.com", Kind: 27235}
	for _, m := range mutate {
		m(&opts)
	}
	return New(opts)
}

func userKey(t *testing.T) (string, string) {
	sk := gonostr.GeneratePrivateKey()
	pk, err := gonostr.GetPublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	return sk, pk
}

func wait(t *testing.T, s *Session) (*gonostr.Event, error) {
	t.Helper()
	select {
	case <-s.Done():
		return s.Result()
	case <-time.After(10 * time.Second):
		t.Fatal("session did not finish")
		return nil, nil
	}
}

func runSigner(t *testing.T, signer *nip46test.Signer, uri string) chan error {
	errc := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	go func() { errc <- signer.Connect(ctx, uri) }()
	return errc
}

func TestRemoteSignerSignsTemplate(t *testing.T) {
	for _, nip04 := range []bool{false, true} {
		relay := nip46test.NewRelay(t)
		m := newManager(t, relay.URL)
		sess, err := m.Start("c1", "b1", testTemplate, time.Now().Add(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}

		u, _ := url.Parse(sess.URI)
		if u.Scheme != "nostrconnect" || u.Query().Get("relay") != relay.URL || len(u.Query().Get("secret")) != 32 ||
			u.Query().Get("perms") != "sign_event:27235" || u.Query().Get("name") != "auth.example.com" {
			t.Fatalf("bad connect URI %q", sess.URI)
		}

		sk, pk := userKey(t)
		signer := &nip46test.Signer{UserKey: sk, UseNIP04: nip04}
		errc := runSigner(t, signer, sess.URI)
		ev, err := wait(t, sess)
		if err != nil {
			t.Fatalf("nip04=%v: %v", nip04, err)
		}
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
		if ev.PubKey != pk || ev.Kind != 27235 || ev.Content != testTemplate.Content || !tagsEqual(ev.Tags, testTemplate.Tags) {
			t.Fatalf("unexpected signed event %+v", ev)
		}
		if ok, _ := ev.CheckSignature(); !ok {
			t.Fatal("signature invalid")
		}
		if d := time.Since(ev.CreatedAt.Time()); d < -2*time.Second || d > 5*time.Second {
			t.Fatalf("created_at %v not current", ev.CreatedAt.Time())
		}
		if signer.Request.Method != "sign_event" {
			t.Fatalf("method %q", signer.Request.Method)
		}
	}
}

func tagsEqual(a, b gonostr.Tags) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], "\x00") != strings.Join(b[i], "\x00") {
			return false
		}
	}
	return true
}

func TestWrongSecretIsIgnored(t *testing.T) {
	relay := nip46test.NewRelay(t)
	m := newManager(t, relay.URL)
	sess, err := m.Start("c1", "b1", testTemplate, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := userKey(t)
	runSigner(t, &nip46test.Signer{UserKey: sk, Secret: strings.Repeat("0", 32)}, sess.URI)
	if _, err := wait(t, sess); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want timeout", err)
	}
}

func TestImpostorWithoutSecretCannotTakeOver(t *testing.T) {
	relay := nip46test.NewRelay(t)
	m := newManager(t, relay.URL)
	sess, err := m.Start("c1", "b1", testTemplate, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	attackerSK, _ := userKey(t)
	impostor := runSigner(t, &nip46test.Signer{UserKey: attackerSK, Secret: "guess"}, sess.URI)

	sk, pk := userKey(t)
	runSigner(t, &nip46test.Signer{UserKey: sk}, sess.URI)
	ev, err := wait(t, sess)
	if err != nil {
		t.Fatal(err)
	}
	if ev.PubKey != pk {
		t.Fatal("event signed by the impostor was accepted")
	}
	select {
	case err := <-impostor:
		t.Fatalf("impostor got a sign request: %v", err)
	default:
	}
}

func TestSignerRefusal(t *testing.T) {
	relay := nip46test.NewRelay(t)
	m := newManager(t, relay.URL)
	sess, _ := m.Start("c1", "b1", testTemplate, time.Now().Add(10*time.Second))
	sk, _ := userKey(t)
	runSigner(t, &nip46test.Signer{UserKey: sk, Refuse: "user rejected\nthe request"}, sess.URI)
	_, err := wait(t, sess)
	if err == nil || !strings.Contains(err.Error(), "refused: user rejected the request") {
		t.Fatalf("got %v", err)
	}
}

func TestSessionPerChallenge(t *testing.T) {
	relay := nip46test.NewRelay(t)
	m := newManager(t, relay.URL, func(o *Options) { o.MaxSessions = 2 })
	exp := time.Now().Add(10 * time.Second)
	a, err := m.Start("c1", "b1", testTemplate, exp)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Start("c1", "b1", testTemplate, exp); again != a {
		t.Fatal("same browser and challenge must reuse the session")
	}
	if _, err := m.Start("c1", "other", testTemplate, exp); !errors.Is(err, ErrInUse) {
		t.Fatalf("got %v, want ErrInUse", err)
	}
	if _, err := m.Start("c2", "b1", testTemplate, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start("c3", "b1", testTemplate, exp); !errors.Is(err, ErrCapacity) {
		t.Fatalf("got %v, want ErrCapacity", err)
	}
	m.Remove(a.ID)
	if m.Get(a.ID) != nil {
		t.Fatal("removed session still found")
	}
	if _, err := a.Result(); err == nil {
		t.Fatal("removed session has no error")
	}
}

func TestRelayAddressGuard(t *testing.T) {
	relay := nip46test.NewRelay(t)
	m := newManager(t, relay.URL, func(o *Options) { o.AllowPrivate = false })
	sess, _ := m.Start("c1", "b1", testTemplate, time.Now().Add(5*time.Second))
	_, err := wait(t, sess)
	if err == nil || !strings.Contains(err.Error(), "could not connect") {
		t.Fatalf("loopback relay was dialled: %v", err)
	}
}
