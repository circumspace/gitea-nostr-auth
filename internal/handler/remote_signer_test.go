package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/circumspace/gitea-nostr-auth/internal/config"
	"github.com/circumspace/gitea-nostr-auth/internal/nip46/nip46test"
)

func newRemoteEnv(t *testing.T) *env {
	relay := nip46test.NewRelay(t)
	return newEnv(t, func(c *config.Config) {
		c.Nostr.NIP46 = config.NIP46Config{Relay: relay.URL, AllowPrivateRelay: true, Timeout: time.Minute}
	})
}

func (e *env) postJSON(c *http.Client, path string, body any, out any) int {
	e.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := c.Post(e.srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(out)
	return resp.StatusCode
}

func (e *env) remoteStart(c *http.Client, challenge string) (int, remoteSignerStartResponse) {
	var r remoteSignerStartResponse
	return e.postJSON(c, "/nip46/start", remoteSignerStartRequest{Challenge: challenge}, &r), r
}

func (e *env) remoteWait(c *http.Client, session string) (int, VerifyResponse) {
	for {
		var vr VerifyResponse
		status := e.postJSON(c, "/nip46/wait", remoteSignerWaitRequest{Session: session}, &vr)
		if !vr.Pending {
			return status, vr
		}
	}
}

func connectSigner(t *testing.T, s *nip46test.Signer, uri string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	go func() { _ = s.Connect(ctx, uri) }()
}

func TestRemoteSignerFullFlow(t *testing.T) {
	e := newRemoteEnv(t)
	resp, a := e.authorize(nil)
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' data:") {
		t.Fatalf("CSP %q", csp)
	}
	status, start := e.remoteStart(e.client, a.challenge)
	if status != http.StatusOK || !strings.HasPrefix(start.URI, "nostrconnect://") ||
		!strings.HasPrefix(start.QR, "data:image/png;base64,") || start.ExpiresIn <= 0 || start.ExpiresIn > 60 {
		t.Fatalf("start: %d %+v", status, start)
	}

	sk, pk := newKey(t)
	connectSigner(t, &nip46test.Signer{UserKey: sk}, start.URI)
	status, vr := e.remoteWait(e.client, start.Session)
	if status != http.StatusOK || !vr.Success {
		t.Fatalf("wait: %d %+v", status, vr)
	}
	code := codeFrom(t, vr.RedirectURL)
	status, tr := e.token(url.Values{"code": {code}}, true)
	if status != http.StatusOK {
		t.Fatalf("token: %d", status)
	}
	if sub := e.parseIDToken(tr.IDToken)["sub"]; sub != pk {
		t.Fatalf("sub %v, want %s", sub, pk)
	}

	if s, _ := e.verify(e.client, e.loginEvent(sk, a)); s != http.StatusBadRequest {
		t.Fatalf("challenge reusable through /verify after remote login: %d", s)
	}
	var gone VerifyResponse
	if s := e.postJSON(e.client, "/nip46/wait", remoteSignerWaitRequest{Session: start.Session}, &gone); s != http.StatusNotFound {
		t.Fatalf("session reusable: %d", s)
	}
}

func TestRemoteSignerBindsBrowser(t *testing.T) {
	e := newRemoteEnv(t)
	_, a := e.authorize(nil)
	other := &http.Client{}

	if s, _ := e.remoteStart(other, a.challenge); s != http.StatusForbidden {
		t.Fatalf("start from another browser: %d", s)
	}
	_, start := e.remoteStart(e.client, a.challenge)
	var vr VerifyResponse
	if s := e.postJSON(other, "/nip46/wait", remoteSignerWaitRequest{Session: start.Session}, &vr); s != http.StatusForbidden {
		t.Fatalf("wait from another browser: %d %+v", s, vr)
	}
	if s, _ := e.remoteStart(e.client, strings.Repeat("0", 64)); s != http.StatusBadRequest {
		t.Fatalf("start with unknown challenge: %d", s)
	}
}

// The signed event goes through the same checks as /verify.
func TestRemoteSignerEventVerified(t *testing.T) {
	cases := map[string]func(*gonostr.Event){
		"content":   func(ev *gonostr.Event) { ev.Content = "Sign in to evil.example via auth" },
		"u tag":     func(ev *gonostr.Event) { ev.Tags[0][1] = "https://evil.example/verify" },
		"challenge": func(ev *gonostr.Event) { ev.Tags[2][1] = strings.Repeat("a", 64) },
		"kind":      func(ev *gonostr.Event) { ev.Kind = 1 },
		"old":       func(ev *gonostr.Event) { ev.CreatedAt -= 3600 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newRemoteEnv(t)
			_, a := e.authorize(nil)
			_, start := e.remoteStart(e.client, a.challenge)
			sk, _ := newKey(t)
			connectSigner(t, &nip46test.Signer{UserKey: sk, Mutate: mutate}, start.URI)
			if s, vr := e.remoteWait(e.client, start.Session); s == http.StatusOK || vr.Success {
				t.Fatalf("mutated event accepted: %d %+v", s, vr)
			}
		})
	}
}

func TestRemoteSignerRefusal(t *testing.T) {
	e := newRemoteEnv(t)
	_, a := e.authorize(nil)
	_, start := e.remoteStart(e.client, a.challenge)
	sk, _ := newKey(t)
	connectSigner(t, &nip46test.Signer{UserKey: sk, Refuse: "rejected"}, start.URI)
	s, vr := e.remoteWait(e.client, start.Session)
	if s != http.StatusBadGateway || !strings.Contains(vr.Error, "rejected") {
		t.Fatalf("refusal: %d %+v", s, vr)
	}
}

func TestRemoteSignerDisabled(t *testing.T) {
	e := newEnv(t)
	resp, a := e.authorize(nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	if s, _ := e.remoteStart(e.client, a.challenge); s != http.StatusNotFound && s != http.StatusMethodNotAllowed {
		t.Fatalf("/nip46/start served while disabled: %d", s)
	}
}
