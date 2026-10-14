// Package nip46 asks a remote signer (NIP-46, Nostr Connect) such as Amber
// to sign a single login event. Each login gets a fresh client keypair, a
// one-time secret and its own subscription on one operator-configured relay.
package nip46

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"

	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
)

const (
	KindNostrConnect = 24133

	DefaultMaxSessions = 64

	subID            = "c"
	maxMessageBytes  = 64 << 10
	maxEventsHandled = 200
	maxErrorLen      = 200
	// sessionGrace keeps a finished session readable for a browser that
	// polls shortly after its deadline.
	sessionGrace = 30 * time.Second
)

var (
	ErrCapacity = errors.New("too many pending remote signer logins, try again later")
	ErrInUse    = errors.New("this challenge is already being signed in another browser")
	ErrTimeout  = errors.New("the remote signer did not respond in time")
)

// Options configure a Manager.
type Options struct {
	// Relay is the only relay used to talk to signers.
	Relay string
	// AllowPrivate disables the non-public address guard for Relay.
	AllowPrivate bool
	// AppName and AppURL are shown by the signer app.
	AppName string
	AppURL  string
	// Kind is the only event kind the signer is asked to allow.
	Kind        int
	MaxSessions int
	// RequestDelay is the wait between the signer's connect answer and the
	// first sign request. Amber starts listening for requests only after it
	// has sent the answer, and misses a request that arrives sooner.
	RequestDelay time.Duration
	// ResendInterval is how often an unanswered sign request is sent again.
	ResendInterval time.Duration
}

const (
	DefaultRequestDelay   = 2 * time.Second
	DefaultResendInterval = 10 * time.Second
)

type Manager struct {
	opts       Options
	httpClient *http.Client

	mu       sync.Mutex
	sessions map[string]*Session
}

// Session is one pending remote signer login.
type Session struct {
	ID string
	// Key identifies what is being signed (the login challenge). There is at
	// most one live session per key.
	Key         string
	BindingHash string
	URI         string
	ExpiresAt   time.Time

	done   chan struct{}
	once   sync.Once
	event  *gonostr.Event
	err    error
	cancel context.CancelFunc
}

// Done is closed when the session has a signed event or has failed.
func (s *Session) Done() <-chan struct{} { return s.done }

// Result returns the signed event or the failure. Valid after Done.
func (s *Session) Result() (*gonostr.Event, error) { return s.event, s.err }

func (s *Session) finish(ev *gonostr.Event, err error) {
	s.once.Do(func() {
		s.event, s.err = ev, err
		close(s.done)
		s.cancel()
	})
}

func New(opts Options) *Manager {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = DefaultMaxSessions
	}
	if opts.RequestDelay <= 0 {
		opts.RequestDelay = DefaultRequestDelay
	}
	if opts.ResendInterval <= 0 {
		opts.ResendInterval = DefaultResendInterval
	}
	return &Manager{
		opts:       opts,
		httpClient: nostr.NewRelayHTTPClient(opts.AllowPrivate),
		sessions:   make(map[string]*Session),
	}
}

// Start creates a session that asks a signer to sign tmpl (kind, tags and
// content; created_at is set when the request is sent). The session ends at
// expires. A second Start for the same key from the same browser returns the
// existing session.
func (m *Manager) Start(key, bindingHash string, tmpl gonostr.Event, expires time.Time) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.sweepLocked(now)
	for _, s := range m.sessions {
		if s.Key != key {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(s.BindingHash), []byte(bindingHash)) != 1 {
			return nil, ErrInUse
		}
		select {
		case <-s.done:
		default:
			return s, nil
		}
	}
	if len(m.sessions) >= m.opts.MaxSessions {
		return nil, ErrCapacity
	}

	id, err := oauth2.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	secret, err := oauth2.GenerateToken(16)
	if err != nil {
		return nil, err
	}
	sk := gonostr.GeneratePrivateKey()
	if sk == "" {
		return nil, errors.New("generating client key failed")
	}
	pk, err := gonostr.GetPublicKey(sk)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithDeadline(context.Background(), expires)
	s := &Session{
		ID:          id,
		Key:         key,
		BindingHash: bindingHash,
		URI:         m.connectURI(pk, secret),
		ExpiresAt:   expires,
		done:        make(chan struct{}),
		cancel:      cancel,
	}
	m.sessions[id] = s

	c := &conversation{m: m, sk: sk, pk: pk, secret: secret, tmpl: tmpl, requestEvIDs: map[string]bool{}}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("nip46: session panicked: %v", r)
				s.finish(nil, errors.New("internal error"))
			}
		}()
		ev, err := c.run(ctx)
		if err != nil {
			log.Printf("nip46: session ended: %v", err)
		}
		s.finish(ev, err)
	}()
	return s, nil
}

// Get returns a live or recently finished session.
func (m *Manager) Get(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || time.Now().After(s.ExpiresAt.Add(sessionGrace)) {
		return nil
	}
	return s
}

// Remove ends and forgets a session.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		s.finish(nil, errors.New("session closed"))
		delete(m.sessions, id)
	}
}

func (m *Manager) sweepLocked(now time.Time) {
	for id, s := range m.sessions {
		if now.After(s.ExpiresAt.Add(sessionGrace)) {
			s.finish(nil, ErrTimeout)
			delete(m.sessions, id)
		}
	}
}

func (m *Manager) connectURI(pk, secret string) string {
	q := url.Values{}
	q.Set("relay", m.opts.Relay)
	q.Set("secret", secret)
	q.Set("perms", fmt.Sprintf("sign_event:%d", m.opts.Kind))
	if m.opts.AppName != "" {
		q.Set("name", m.opts.AppName)
	}
	if m.opts.AppURL != "" {
		q.Set("url", m.opts.AppURL)
	}
	return "nostrconnect://" + pk + "?" + q.Encode()
}

type request struct {
	ID     string   `json:"id"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

type response struct {
	ID     string `json:"id"`
	Result string `json:"result"`
	Error  string `json:"error"`
}

type unsignedEvent struct {
	Kind      int               `json:"kind"`
	CreatedAt gonostr.Timestamp `json:"created_at"`
	Tags      gonostr.Tags      `json:"tags"`
	Content   string            `json:"content"`
}

type conversation struct {
	m      *Manager
	conn   *websocket.Conn
	sk, pk string
	secret string
	tmpl   gonostr.Event

	signer       string
	requestID    string
	requestEvIDs map[string]bool
}

func (c *conversation) run(ctx context.Context) (*gonostr.Event, error) {
	conn, resp, err := websocket.Dial(ctx, c.m.opts.Relay, &websocket.DialOptions{
		HTTPClient: c.m.httpClient,
		HTTPHeader: http.Header{"User-Agent": {"gitea-nostr-auth"}},
	})
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrTimeout
		}
		log.Printf("nip46: relay %s: %v", c.m.opts.Relay, err)
		return nil, errors.New("could not connect to the signer relay")
	}
	c.conn = conn
	defer conn.CloseNow()
	conn.SetReadLimit(maxMessageBytes)

	since := gonostr.Timestamp(time.Now().Add(-time.Minute).Unix())
	filter := gonostr.Filter{
		Kinds: []int{KindNostrConnect},
		Tags:  gonostr.TagMap{"p": {c.pk}},
		Since: &since,
	}
	req, err := gonostr.ReqEnvelope{SubscriptionID: subID, Filters: gonostr.Filters{filter}}.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := conn.Write(ctx, websocket.MessageText, req); err != nil {
		return nil, c.relayErr(ctx, err)
	}
	c.logf("subscribed on %s", c.m.opts.Relay)

	msgs := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			select {
			case msgs <- data:
			case <-ctx.Done():
				return
			}
		}
	}()

	var send <-chan time.Time
	attempts := 0
	for handled := 0; handled < maxEventsHandled; {
		var data []byte
		select {
		case err := <-readErr:
			return nil, c.relayErr(ctx, err)
		case <-send:
			attempts++
			c.logf("sending the sign request (attempt %d)", attempts)
			if err := c.requestSignature(ctx); err != nil {
				return nil, err
			}
			send = time.After(c.m.opts.ResendInterval)
			continue
		case data = <-msgs:
		}
		var msg []json.RawMessage
		if json.Unmarshal(data, &msg) != nil || len(msg) < 2 {
			continue
		}
		var label string
		if json.Unmarshal(msg[0], &label) != nil {
			continue
		}
		switch label {
		case "OK":
			var id, reason string
			var accepted bool
			if len(msg) < 3 || json.Unmarshal(msg[1], &id) != nil || json.Unmarshal(msg[2], &accepted) != nil {
				continue
			}
			if len(msg) > 3 {
				_ = json.Unmarshal(msg[3], &reason)
			}
			if c.requestEvIDs[id] && !accepted {
				return nil, fmt.Errorf("the signer relay rejected the signing request: %s", truncate(reason))
			}
		case "CLOSED":
			var sid string
			if json.Unmarshal(msg[1], &sid) == nil && sid == subID {
				return nil, errors.New("the signer relay closed the subscription")
			}
		case "EVENT":
			var sid string
			if len(msg) < 3 || json.Unmarshal(msg[1], &sid) != nil || sid != subID {
				continue
			}
			handled++
			var ev gonostr.Event
			if json.Unmarshal(msg[2], &ev) != nil || !filter.Matches(&ev) || !nostr.ValidEvent(&ev) {
				c.logf("dropped an invalid or unexpected event from the relay")
				continue
			}
			connected := c.signer != ""
			signed, err := c.handle(ctx, &ev)
			if signed != nil || err != nil {
				return signed, err
			}
			if !connected && c.signer != "" {
				send = time.After(c.m.opts.RequestDelay)
			}
		}
	}
	return nil, errors.New("too many messages from the signer relay")
}

// handle processes one verified kind-24133 event addressed to the client
// key. It returns a signed event or a terminal error, or neither if the
// event is ignored.
func (c *conversation) handle(ctx context.Context, ev *gonostr.Event) (*gonostr.Event, error) {
	resp, ok := c.decrypt(ev)
	if !ok {
		c.logf("ignored a message from %s that does not decrypt", short(ev.PubKey))
		return nil, nil
	}

	if c.signer == "" {
		if subtle.ConstantTimeCompare([]byte(resp.Result), []byte(c.secret)) != 1 {
			c.logf("ignored a message from %s without the session secret (id %q, error %q)", short(ev.PubKey), truncate(resp.ID), truncate(resp.Error))
			return nil, nil
		}
		id, err := oauth2.GenerateToken(8)
		if err != nil {
			return nil, err
		}
		c.signer = ev.PubKey
		c.requestID = id
		c.logf("signer %s connected", short(ev.PubKey))
		return nil, nil
	}

	if ev.PubKey != c.signer {
		c.logf("ignored a message from %s, which is not the session's signer", short(ev.PubKey))
		return nil, nil
	}
	if resp.ID != c.requestID {
		c.logf("ignored a response for request %q, expected %q", truncate(resp.ID), c.requestID)
		return nil, nil
	}
	c.logf("signer answered the sign request")
	if resp.Result == "auth_url" {
		return nil, errors.New("the signer asked for a web authorization step, which is not supported")
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("the signer refused: %s", truncate(resp.Error))
	}
	var signed gonostr.Event
	if err := json.Unmarshal([]byte(resp.Result), &signed); err != nil {
		return nil, errors.New("the signer returned an invalid event")
	}
	return &signed, nil
}

func (c *conversation) decrypt(ev *gonostr.Event) (response, bool) {
	var resp response
	var plain string
	key, err := nip44.GenerateConversationKey(ev.PubKey, c.sk)
	if err != nil {
		return resp, false
	}
	plain, err = nip44.Decrypt(ev.Content, key)
	if err != nil || json.Unmarshal([]byte(plain), &resp) != nil {
		return resp, false
	}
	return resp, true
}

func (c *conversation) requestSignature(ctx context.Context) error {
	unsigned, err := json.Marshal(unsignedEvent{
		Kind:      c.tmpl.Kind,
		CreatedAt: gonostr.Now(),
		Tags:      c.tmpl.Tags,
		Content:   c.tmpl.Content,
	})
	if err != nil {
		return err
	}
	body, err := json.Marshal(request{ID: c.requestID, Method: "sign_event", Params: []string{string(unsigned)}})
	if err != nil {
		return err
	}
	key, err := nip44.GenerateConversationKey(c.signer, c.sk)
	if err != nil {
		return err
	}
	content, err := nip44.Encrypt(string(body), key)
	if err != nil {
		return err
	}
	ev := gonostr.Event{
		Kind:      KindNostrConnect,
		CreatedAt: gonostr.Now(),
		Tags:      gonostr.Tags{{"p", c.signer}},
		Content:   content,
	}
	if err := ev.Sign(c.sk); err != nil {
		return err
	}
	c.requestEvIDs[ev.ID] = true
	msg, err := json.Marshal([]any{"EVENT", ev})
	if err != nil {
		return err
	}
	if err := c.conn.Write(ctx, websocket.MessageText, msg); err != nil {
		return c.relayErr(ctx, err)
	}
	return nil
}

func (c *conversation) relayErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ErrTimeout
	}
	log.Printf("nip46: relay %s: %v", c.m.opts.Relay, err)
	return errors.New("lost the connection to the signer relay")
}

func (c *conversation) logf(format string, args ...any) {
	log.Printf("nip46 %s: "+format, append([]any{short(c.pk)}, args...)...)
}

func short(pubkey string) string {
	if len(pubkey) > 8 {
		return pubkey[:8]
	}
	return pubkey
}

func truncate(s string) string {
	r := []rune(s)
	if len(r) > maxErrorLen {
		r = r[:maxErrorLen]
	}
	return strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return ' '
		}
		return c
	}, string(r))
}
