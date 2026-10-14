// Package nip46test provides an in-memory relay and a scripted remote
// signer for tests.
package nip46test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

const kindNostrConnect = 24133

// Relay is a minimal relay: it stores events and forwards them to matching
// subscriptions.
type Relay struct {
	URL string

	mu     sync.Mutex
	events []*gonostr.Event
	subs   map[*relayConn]map[string]gonostr.Filters
}

type relayConn struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (rc *relayConn) send(ctx context.Context, v any) {
	b, _ := json.Marshal(v)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	_ = rc.c.Write(ctx, websocket.MessageText, b)
}

func NewRelay(t *testing.T) *Relay {
	r := &Relay{subs: map[*relayConn]map[string]gonostr.Filters{}}
	srv := httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(srv.Close)
	r.URL = "ws" + strings.TrimPrefix(srv.URL, "http")
	return r
}

func (r *Relay) serve(w http.ResponseWriter, req *http.Request) {
	c, err := websocket.Accept(w, req, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	rc := &relayConn{c: c}
	ctx := req.Context()
	defer func() {
		r.mu.Lock()
		delete(r.subs, rc)
		r.mu.Unlock()
	}()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var msg []json.RawMessage
		if json.Unmarshal(data, &msg) != nil || len(msg) < 2 {
			continue
		}
		var label string
		_ = json.Unmarshal(msg[0], &label)
		switch label {
		case "EVENT":
			var ev gonostr.Event
			if json.Unmarshal(msg[1], &ev) != nil {
				continue
			}
			ok, _ := ev.CheckSignature()
			rc.send(ctx, []any{"OK", ev.ID, ok, ""})
			if ok {
				r.publish(ctx, &ev)
			}
		case "REQ":
			var sid string
			_ = json.Unmarshal(msg[1], &sid)
			var filters gonostr.Filters
			for _, raw := range msg[2:] {
				var f gonostr.Filter
				if json.Unmarshal(raw, &f) == nil {
					filters = append(filters, f)
				}
			}
			r.mu.Lock()
			if r.subs[rc] == nil {
				r.subs[rc] = map[string]gonostr.Filters{}
			}
			r.subs[rc][sid] = filters
			liveOnly := false
			for _, f := range filters {
				liveOnly = liveOnly || f.LimitZero
			}
			var stored []*gonostr.Event
			for _, ev := range r.events {
				if !liveOnly && filters.Match(ev) {
					stored = append(stored, ev)
				}
			}
			r.mu.Unlock()
			for _, ev := range stored {
				rc.send(ctx, []any{"EVENT", sid, ev})
			}
			rc.send(ctx, []any{"EOSE", sid})
		}
	}
}

// Publish stores an event and forwards it, as if a client had sent it.
func (r *Relay) Publish(ev *gonostr.Event) { r.publish(context.Background(), ev) }

func (r *Relay) publish(ctx context.Context, ev *gonostr.Event) {
	type delivery struct {
		rc  *relayConn
		sid string
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	var out []delivery
	for rc, subs := range r.subs {
		for sid, filters := range subs {
			if filters.Match(ev) {
				out = append(out, delivery{rc, sid})
			}
		}
	}
	r.mu.Unlock()
	for _, d := range out {
		d.rc.send(ctx, []any{"EVENT", d.sid, ev})
	}
}

// Signer is a scripted NIP-46 remote signer holding the user's key.
type Signer struct {
	UserKey string
	// Secret, if set, replaces the secret from the connect URI.
	Secret string
	// UseNIP04 encrypts responses with NIP-04 instead of NIP-44, which the
	// server does not accept.
	UseNIP04 bool
	// Refuse answers sign_event with this error.
	Refuse string
	// ListenAfterConnect makes the signer behave like Amber: it sends its
	// connect answer first and only then, after this delay, subscribes for
	// new requests, so it misses any request sent in between.
	ListenAfterConnect time.Duration
	// Mutate changes the event template before it is signed.
	Mutate func(*gonostr.Event)

	// Request is the last sign_event request received.
	Request struct {
		Method string
		Params []string
	}
}

type rpcRequest struct {
	ID     string   `json:"id"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

type rpcResponse struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Connect answers a nostrconnect:// URI and serves one sign_event request.
// It returns when the response has been published or ctx ends.
func (s *Signer) Connect(ctx context.Context, uri string) error {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "nostrconnect" {
		return errors.New("bad nostrconnect URI")
	}
	clientPK := u.Host
	q := u.Query()
	secret := q.Get("secret")
	if s.Secret != "" {
		secret = s.Secret
	}
	if q.Get("perms") != "sign_event:27235" {
		return errors.New("unexpected perms " + q.Get("perms"))
	}

	signerSK := gonostr.GeneratePrivateKey()
	signerPK, _ := gonostr.GetPublicKey(signerSK)

	c, _, err := websocket.Dial(ctx, q.Get("relay"), nil)
	if err != nil {
		return err
	}
	defer c.CloseNow()
	var lastSent string
	send := func(v any) error {
		b, _ := json.Marshal(v)
		return c.Write(ctx, websocket.MessageText, b)
	}
	respond := func(r rpcResponse) error {
		body, _ := json.Marshal(r)
		var content string
		if s.UseNIP04 {
			shared, _ := nip04.ComputeSharedSecret(clientPK, signerSK)
			content, _ = nip04.Encrypt(string(body), shared)
		} else {
			key, _ := nip44.GenerateConversationKey(clientPK, signerSK)
			content, _ = nip44.Encrypt(string(body), key)
		}
		ev := gonostr.Event{Kind: kindNostrConnect, CreatedAt: gonostr.Now(), Tags: gonostr.Tags{{"p", clientPK}}, Content: content}
		if err := ev.Sign(signerSK); err != nil {
			return err
		}
		lastSent = ev.ID
		return send([]any{"EVENT", ev})
	}
	awaitOK := func(id string) error {
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return err
			}
			var msg []json.RawMessage
			if json.Unmarshal(data, &msg) != nil || len(msg) < 3 {
				continue
			}
			var label, got string
			var accepted bool
			_ = json.Unmarshal(msg[0], &label)
			_ = json.Unmarshal(msg[1], &got)
			_ = json.Unmarshal(msg[2], &accepted)
			if label == "OK" && got == id {
				if !accepted {
					return errors.New("relay rejected the response")
				}
				return nil
			}
		}
	}
	finish := func(r rpcResponse) error {
		if err := respond(r); err != nil {
			return err
		}
		return awaitOK(lastSent)
	}

	subscribe := func() error {
		f := gonostr.Filter{Kinds: []int{kindNostrConnect}, Tags: gonostr.TagMap{"p": {signerPK}}, LimitZero: s.ListenAfterConnect > 0}
		return send([]any{"REQ", "s", f})
	}
	if s.ListenAfterConnect == 0 {
		if err := subscribe(); err != nil {
			return err
		}
	}
	connectID, _ := json.Marshal(time.Now().UnixNano())
	if err := respond(rpcResponse{ID: string(connectID), Result: secret}); err != nil {
		return err
	}
	if s.ListenAfterConnect > 0 {
		if err := awaitOK(lastSent); err != nil {
			return err
		}
		time.Sleep(s.ListenAfterConnect)
		if err := subscribe(); err != nil {
			return err
		}
	}

	key, _ := nip44.GenerateConversationKey(clientPK, signerSK)
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		var msg []json.RawMessage
		if json.Unmarshal(data, &msg) != nil || len(msg) < 3 {
			continue
		}
		var label string
		_ = json.Unmarshal(msg[0], &label)
		if label != "EVENT" {
			continue
		}
		var ev gonostr.Event
		if json.Unmarshal(msg[2], &ev) != nil || ev.PubKey != clientPK {
			continue
		}
		plain, err := nip44.Decrypt(ev.Content, key)
		if err != nil {
			return err
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(plain), &req); err != nil {
			return err
		}
		s.Request.Method, s.Request.Params = req.Method, req.Params
		if req.Method != "sign_event" || len(req.Params) != 1 {
			return finish(rpcResponse{ID: req.ID, Error: "unsupported"})
		}
		if s.Refuse != "" {
			return finish(rpcResponse{ID: req.ID, Error: s.Refuse})
		}
		var tmpl gonostr.Event
		if err := json.Unmarshal([]byte(req.Params[0]), &tmpl); err != nil {
			return err
		}
		if s.Mutate != nil {
			s.Mutate(&tmpl)
		}
		if err := tmpl.Sign(s.UserKey); err != nil {
			return err
		}
		signed, _ := json.Marshal(tmpl)
		return finish(rpcResponse{ID: req.ID, Result: string(signed)})
	}
}
