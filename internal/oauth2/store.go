package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// AuthCode represents an OAuth2 authorization code
type AuthCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Pubkey      string // Nostr public key (hex)
	State       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Challenge represents a Nostr authentication challenge
type Challenge struct {
	Nonce     string
	ClientID  string
	State     string
	RedirectURI string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AccessToken represents an issued access token
type AccessToken struct {
	Token     string
	Pubkey    string
	ClientID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store interface for OAuth2 data persistence
type Store interface {
	// Challenge operations
	CreateChallenge(clientID, state, redirectURI string, ttl time.Duration) (*Challenge, error)
	GetChallenge(nonce string) (*Challenge, error)
	DeleteChallenge(nonce string) error

	// Auth code operations
	CreateAuthCode(clientID, redirectURI, pubkey, state string) (*AuthCode, error)
	GetAuthCode(code string) (*AuthCode, error)
	DeleteAuthCode(code string) error

	// Access token operations
	CreateAccessToken(pubkey, clientID string) (*AccessToken, error)
	GetAccessToken(token string) (*AccessToken, error)
}

// MemoryStore is an in-memory implementation of Store
type MemoryStore struct {
	challenges   map[string]*Challenge
	authCodes    map[string]*AuthCode
	accessTokens map[string]*AccessToken
	mu           sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		challenges:   make(map[string]*Challenge),
		authCodes:    make(map[string]*AuthCode),
		accessTokens: make(map[string]*AccessToken),
	}
	go s.cleanup()
	return s
}

func (s *MemoryStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		s.mu.Lock()
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
		s.mu.Unlock()
	}
}

func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *MemoryStore) CreateChallenge(clientID, state, redirectURI string, ttl time.Duration) (*Challenge, error) {
	nonce, err := generateToken(32)
	if err != nil {
		return nil, err
	}

	challenge := &Challenge{
		Nonce:       nonce,
		ClientID:    clientID,
		State:       state,
		RedirectURI: redirectURI,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
	}

	s.mu.Lock()
	s.challenges[nonce] = challenge
	s.mu.Unlock()

	return challenge, nil
}

func (s *MemoryStore) GetChallenge(nonce string) (*Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	challenge, ok := s.challenges[nonce]
	if !ok || time.Now().After(challenge.ExpiresAt) {
		return nil, nil
	}
	return challenge, nil
}

func (s *MemoryStore) DeleteChallenge(nonce string) error {
	s.mu.Lock()
	delete(s.challenges, nonce)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) CreateAuthCode(clientID, redirectURI, pubkey, state string) (*AuthCode, error) {
	code, err := generateToken(32)
	if err != nil {
		return nil, err
	}

	authCode := &AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Pubkey:      pubkey,
		State:       state,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	s.mu.Lock()
	s.authCodes[code] = authCode
	s.mu.Unlock()

	return authCode, nil
}

func (s *MemoryStore) GetAuthCode(code string) (*AuthCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, ok := s.authCodes[code]
	if !ok || time.Now().After(authCode.ExpiresAt) {
		return nil, nil
	}
	return authCode, nil
}

func (s *MemoryStore) DeleteAuthCode(code string) error {
	s.mu.Lock()
	delete(s.authCodes, code)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) CreateAccessToken(pubkey, clientID string) (*AccessToken, error) {
	token, err := generateToken(32)
	if err != nil {
		return nil, err
	}

	accessToken := &AccessToken{
		Token:     token,
		Pubkey:    pubkey,
		ClientID:  clientID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	s.mu.Lock()
	s.accessTokens[token] = accessToken
	s.mu.Unlock()

	return accessToken, nil
}

func (s *MemoryStore) GetAccessToken(token string) (*AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessToken, ok := s.accessTokens[token]
	if !ok || time.Now().After(accessToken.ExpiresAt) {
		return nil, nil
	}
	return accessToken, nil
}
