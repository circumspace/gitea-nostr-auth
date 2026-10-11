package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Capacity limits for the in-memory store. They bound memory use under
// flooding; legitimate load for a single Gitea instance is far below them.
const (
	MaxChallenges   = 10000
	MaxAuthCodes    = 10000
	MaxAccessTokens = 100000
)

var (
	// ErrCapacity is returned when a store map is full.
	ErrCapacity = errors.New("store capacity exceeded")
	// ErrCodeReused is returned when an authorization code is presented a
	// second time. Tokens issued for it have been revoked.
	ErrCodeReused = errors.New("authorization code reused")
)

// AuthRequest holds the parameters of an authorization request that are
// bound to a challenge and then to the authorization code.
type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string // OIDC nonce
	CodeChallenge       string // PKCE (S256 only)
	CodeChallengeMethod string
}

// Challenge represents a Nostr authentication challenge.
type Challenge struct {
	Nonce string // random challenge value signed by the user
	AuthRequest
	// BindingHash is the SHA-256 (hex) of the browser binding cookie value.
	BindingHash string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// AuthCode represents an OAuth2 authorization code.
type AuthCode struct {
	Code string
	AuthRequest
	Pubkey    string // Nostr public key (hex)
	AuthTime  time.Time
	CreatedAt time.Time
	ExpiresAt time.Time

	used        bool
	issuedToken string
}

// AccessToken represents an issued access token.
type AccessToken struct {
	Token     string
	Pubkey    string
	ClientID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store is the persistence interface for OAuth2 state.
type Store interface {
	CreateChallenge(req AuthRequest, bindingHash string, ttl time.Duration) (*Challenge, error)
	// ConsumeChallenge atomically looks up and deletes a challenge. It
	// returns nil if the challenge does not exist or has expired.
	ConsumeChallenge(nonce string) (*Challenge, error)
	// GetChallenge returns a copy of a live challenge without consuming it,
	// or nil.
	GetChallenge(nonce string) (*Challenge, error)

	CreateAuthCode(req AuthRequest, pubkey string, authTime time.Time, ttl time.Duration) (*AuthCode, error)
	// ConsumeAuthCode atomically marks a code as used and returns it. A
	// second call for the same code returns ErrCodeReused and revokes the
	// access token recorded with BindToken.
	ConsumeAuthCode(code string) (*AuthCode, error)
	// BindToken records the access token issued for a consumed code.
	BindToken(code, token string)

	CreateAccessToken(pubkey, clientID string, ttl time.Duration) (*AccessToken, error)
	GetAccessToken(token string) (*AccessToken, error)
	RevokeAccessToken(token string)
}

// MemoryStore is an in-memory implementation of Store.
type MemoryStore struct {
	challenges   map[string]*Challenge
	authCodes    map[string]*AuthCode
	accessTokens map[string]*AccessToken
	mu           sync.Mutex
	stop         chan struct{}
	stopOnce     sync.Once
}

func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		challenges:   make(map[string]*Challenge),
		authCodes:    make(map[string]*AuthCode),
		accessTokens: make(map[string]*AccessToken),
		stop:         make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close stops the cleanup goroutine.
func (s *MemoryStore) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stop:
			return
		}
	}
}

func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.challenges {
		if now.After(v.ExpiresAt) {
			delete(s.challenges, k)
		}
	}
	for k, v := range s.authCodes {
		if now.After(v.ExpiresAt) {
			delete(s.authCodes, k)
		}
	}
	for k, v := range s.accessTokens {
		if now.After(v.ExpiresAt) {
			delete(s.accessTokens, k)
		}
	}
}

// GenerateToken returns length random bytes from crypto/rand, hex encoded.
func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *MemoryStore) CreateChallenge(req AuthRequest, bindingHash string, ttl time.Duration) (*Challenge, error) {
	nonce, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c := &Challenge{
		Nonce:       nonce,
		AuthRequest: req,
		BindingHash: bindingHash,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.challenges) >= MaxChallenges {
		s.cleanupChallengesLocked(now)
		if len(s.challenges) >= MaxChallenges {
			return nil, ErrCapacity
		}
	}
	s.challenges[nonce] = c
	return c, nil
}

func (s *MemoryStore) cleanupChallengesLocked(now time.Time) {
	for k, v := range s.challenges {
		if now.After(v.ExpiresAt) {
			delete(s.challenges, k)
		}
	}
}

func (s *MemoryStore) ConsumeChallenge(nonce string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[nonce]
	if !ok {
		return nil, nil
	}
	delete(s.challenges, nonce)
	if time.Now().After(c.ExpiresAt) {
		return nil, nil
	}
	return c, nil
}

func (s *MemoryStore) GetChallenge(nonce string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[nonce]
	if !ok || time.Now().After(c.ExpiresAt) {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (s *MemoryStore) CreateAuthCode(req AuthRequest, pubkey string, authTime time.Time, ttl time.Duration) (*AuthCode, error) {
	code, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ac := &AuthCode{
		Code:        code,
		AuthRequest: req,
		Pubkey:      pubkey,
		AuthTime:    authTime,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.authCodes) >= MaxAuthCodes {
		for k, v := range s.authCodes {
			if now.After(v.ExpiresAt) {
				delete(s.authCodes, k)
			}
		}
		if len(s.authCodes) >= MaxAuthCodes {
			return nil, ErrCapacity
		}
	}
	s.authCodes[code] = ac
	return ac, nil
}

func (s *MemoryStore) ConsumeAuthCode(code string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.authCodes[code]
	if !ok || time.Now().After(ac.ExpiresAt) {
		return nil, nil
	}
	if ac.used {
		// RFC 6749 4.1.2: revoke tokens previously issued for this code.
		if ac.issuedToken != "" {
			delete(s.accessTokens, ac.issuedToken)
		}
		delete(s.authCodes, code)
		return nil, ErrCodeReused
	}
	ac.used = true // tombstone kept until expiry to detect reuse
	cp := *ac
	return &cp, nil
}

func (s *MemoryStore) BindToken(code, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ac, ok := s.authCodes[code]; ok {
		ac.issuedToken = token
	}
}

func (s *MemoryStore) CreateAccessToken(pubkey, clientID string, ttl time.Duration) (*AccessToken, error) {
	token, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	at := &AccessToken{
		Token:     token,
		Pubkey:    pubkey,
		ClientID:  clientID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.accessTokens) >= MaxAccessTokens {
		for k, v := range s.accessTokens {
			if now.After(v.ExpiresAt) {
				delete(s.accessTokens, k)
			}
		}
		if len(s.accessTokens) >= MaxAccessTokens {
			return nil, ErrCapacity
		}
	}
	s.accessTokens[token] = at
	return at, nil
}

func (s *MemoryStore) GetAccessToken(token string) (*AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.accessTokens[token]
	if !ok || time.Now().After(at.ExpiresAt) {
		return nil, nil
	}
	cp := *at
	return &cp, nil
}

func (s *MemoryStore) RevokeAccessToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, token)
}
