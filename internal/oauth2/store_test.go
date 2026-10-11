package oauth2

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func req() AuthRequest {
	return AuthRequest{ClientID: "gitea", RedirectURI: "https://g.example.com/cb", State: "s"}
}

func TestChallengeSingleUse(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	c, err := s.CreateChallenge(req(), "h", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Nonce) != 64 {
		t.Fatalf("nonce length %d, want 64 hex chars (256 bit)", len(c.Nonce))
	}
	got, _ := s.ConsumeChallenge(c.Nonce)
	if got == nil || got.State != "s" || got.BindingHash != "h" {
		t.Fatalf("unexpected challenge %+v", got)
	}
	if again, _ := s.ConsumeChallenge(c.Nonce); again != nil {
		t.Fatal("challenge consumed twice")
	}
}

func TestChallengeExpiry(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	c, _ := s.CreateChallenge(req(), "h", 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if got, _ := s.ConsumeChallenge(c.Nonce); got != nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestConcurrentConsumeOnlyOnce(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	c, _ := s.CreateChallenge(req(), "h", time.Minute)
	code, _ := s.CreateAuthCode(req(), "pk", time.Now(), time.Minute)

	var chWins, codeWins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got, _ := s.ConsumeChallenge(c.Nonce); got != nil {
				chWins.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			if got, err := s.ConsumeAuthCode(code.Code); got != nil && err == nil {
				codeWins.Add(1)
			}
		}()
	}
	wg.Wait()
	if chWins.Load() != 1 || codeWins.Load() != 1 {
		t.Fatalf("challenge wins %d, code wins %d; want exactly 1 each", chWins.Load(), codeWins.Load())
	}
}

func TestCodeReuseRevokesToken(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	code, _ := s.CreateAuthCode(req(), "pk", time.Now(), time.Minute)
	if got, err := s.ConsumeAuthCode(code.Code); got == nil || err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	tok, _ := s.CreateAccessToken("pk", "gitea", time.Minute)
	s.BindToken(code.Code, tok.Token)

	got, err := s.ConsumeAuthCode(code.Code)
	if got != nil || !errors.Is(err, ErrCodeReused) {
		t.Fatalf("reuse not detected: %v %v", got, err)
	}
	if at, _ := s.GetAccessToken(tok.Token); at != nil {
		t.Fatal("token issued for reused code is still valid")
	}
}

func TestCodeExpiry(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	code, _ := s.CreateAuthCode(req(), "pk", time.Now(), 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if got, _ := s.ConsumeAuthCode(code.Code); got != nil {
		t.Fatal("expired code accepted")
	}
}

func TestAccessTokenExpiryAndRevoke(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	tok, _ := s.CreateAccessToken("pk", "gitea", 10*time.Millisecond)
	if at, _ := s.GetAccessToken(tok.Token); at == nil {
		t.Fatal("fresh token rejected")
	}
	time.Sleep(30 * time.Millisecond)
	if at, _ := s.GetAccessToken(tok.Token); at != nil {
		t.Fatal("expired token accepted")
	}
	tok2, _ := s.CreateAccessToken("pk", "gitea", time.Minute)
	s.RevokeAccessToken(tok2.Token)
	if at, _ := s.GetAccessToken(tok2.Token); at != nil {
		t.Fatal("revoked token accepted")
	}
}

func TestChallengeCapacity(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()
	for i := 0; i < MaxChallenges; i++ {
		if _, err := s.CreateChallenge(req(), "h", time.Minute); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, err := s.CreateChallenge(req(), "h", time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected ErrCapacity, got %v", err)
	}
}
