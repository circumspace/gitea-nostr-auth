package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
)

// KindHTTPAuth is the NIP-98 HTTP Auth event kind.
const KindHTTPAuth = 27235

// maxClockSkew is the tolerated difference between the event timestamp and
// the server clock in the future direction.
const maxClockSkew = 60 * time.Second

type VerifyResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

func writeVerify(w http.ResponseWriter, status int, resp VerifyResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// checkEvent validates a login event independently of the stored challenge
// and returns the challenge nonce it carries.
func (h *Handler) checkEvent(ev *gonostr.Event, now time.Time) (string, error) {
	if ev.Kind != KindHTTPAuth {
		return "", fmt.Errorf("invalid event kind, expected %d", KindHTTPAuth)
	}
	created := ev.CreatedAt.Time()
	if now.Sub(created) > h.cfg.Nostr.ChallengeTTL {
		return "", errors.New("event timestamp too old")
	}
	if created.Sub(now) > maxClockSkew {
		return "", errors.New("event timestamp in future")
	}
	// id must be the hash of the canonical serialisation and the signature
	// must verify over that hash; never trust the supplied id alone.
	if !nostr.ValidEvent(ev) {
		return "", errors.New("invalid event id or signature")
	}

	var challenge, u, method []string
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "challenge":
			challenge = append(challenge, t[1])
		case "u":
			u = append(u, t[1])
		case "method":
			method = append(method, t[1])
		}
	}
	if len(challenge) != 1 || challenge[0] == "" {
		return "", errors.New("event must contain exactly one challenge tag")
	}
	if len(u) != 1 || u[0] != h.verifyURL() {
		return "", errors.New("event u tag does not match this server's verify URL")
	}
	if len(method) != 1 || method[0] != http.MethodPost {
		return "", errors.New("event method tag must be POST")
	}
	return challenge[0], nil
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeVerify(w, http.StatusUnsupportedMediaType, VerifyResponse{Error: "content type must be application/json"})
		return
	}

	var ev gonostr.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: "invalid event JSON"})
		return
	}

	nonce, err := h.checkEvent(&ev, h.now())
	if err != nil {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: err.Error()})
		return
	}

	// Atomically consume the challenge: a challenge yields at most one code.
	challenge, err := h.store.ConsumeChallenge(nonce)
	if err != nil || challenge == nil {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: "invalid or expired challenge"})
		return
	}
	if !h.bindingMatches(r, challenge.BindingHash) {
		writeVerify(w, http.StatusForbidden, VerifyResponse{Error: "challenge was issued to a different browser"})
		return
	}
	if ev.Content != h.signingStatement(challenge.RedirectURI) {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: "event content does not match the sign-in statement"})
		return
	}
	if ev.CreatedAt.Time().Before(challenge.CreatedAt.Add(-maxClockSkew)) {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: "event predates the challenge"})
		return
	}

	authCode, err := h.store.CreateAuthCode(challenge.AuthRequest, ev.PubKey, h.now(), h.cfg.OAuth2.CodeTTL)
	if err != nil {
		if errors.Is(err, oauth2.ErrCapacity) {
			writeVerify(w, http.StatusServiceUnavailable, VerifyResponse{Error: "server busy, try again later"})
			return
		}
		log.Printf("failed to create auth code: %v", err)
		writeVerify(w, http.StatusInternalServerError, VerifyResponse{Error: "internal error"})
		return
	}

	redirectURL, err := url.Parse(challenge.RedirectURI)
	if err != nil {
		writeVerify(w, http.StatusInternalServerError, VerifyResponse{Error: "internal error"})
		return
	}
	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if challenge.State != "" {
		q.Set("state", challenge.State)
	}
	q.Set("iss", h.cfg.Server.BaseURL) // RFC 9207
	redirectURL.RawQuery = q.Encode()

	h.clearBindingCookie(w)
	log.Printf("login: %s for client %s", nostr.TruncateNpub(nostr.PubkeyToNpub(ev.PubKey)), challenge.ClientID)
	writeVerify(w, http.StatusOK, VerifyResponse{Success: true, RedirectURL: redirectURL.String()})
}
