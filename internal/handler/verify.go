package handler

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"next.orly.dev/pkg/nostr/encoders/event"
	"next.orly.dev/pkg/nostr/encoders/hex"
)

type VerifyResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Read the raw JSON body — event.E.Unmarshal handles hex→binary conversion
	body, err := io.ReadAll(r.Body)
	if err != nil {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "invalid request body"})
		return
	}

	var ev event.E
	if _, err := ev.Unmarshal(body); err != nil {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "invalid event JSON"})
		return
	}

	// Verify event kind (NIP-98 HTTP Auth)
	if ev.Kind != 27235 {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "invalid event kind, expected 27235"})
		return
	}

	// Verify timestamp is within window
	eventTime := time.Unix(ev.CreatedAt, 0)
	if time.Since(eventTime) > h.cfg.Nostr.ChallengeTTL {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "event timestamp too old"})
		return
	}
	if eventTime.After(time.Now().Add(time.Minute)) {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "event timestamp in future"})
		return
	}

	// Verify signature
	ok, err := ev.Verify()
	if err != nil || !ok {
		log.Printf("signature verification failed: %v", err)
		json.NewEncoder(w).Encode(VerifyResponse{Error: "invalid signature"})
		return
	}

	// Extract challenge from tags
	var challengeNonce string
	if ev.Tags != nil {
		for _, t := range *ev.Tags {
			ss := t.ToSliceOfStrings()
			if len(ss) >= 2 && ss[0] == "challenge" {
				challengeNonce = ss[1]
				break
			}
		}
	}

	if challengeNonce == "" {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "missing challenge tag"})
		return
	}

	// Look up challenge
	challenge, err := h.store.GetChallenge(challengeNonce)
	if err != nil || challenge == nil {
		json.NewEncoder(w).Encode(VerifyResponse{Error: "invalid or expired challenge"})
		return
	}

	// Delete challenge (single use)
	h.store.DeleteChallenge(challengeNonce)

	// Convert binary pubkey to hex string for storage
	pubkeyHex := string(hex.Enc(ev.Pubkey))

	// Create authorization code
	authCode, err := h.store.CreateAuthCode(
		challenge.ClientID,
		challenge.RedirectURI,
		pubkeyHex,
		challenge.State,
	)
	if err != nil {
		log.Printf("failed to create auth code: %v", err)
		json.NewEncoder(w).Encode(VerifyResponse{Error: "internal error"})
		return
	}

	// Build redirect URL
	redirectURL, err := url.Parse(challenge.RedirectURI)
	if err != nil {
		log.Printf("invalid redirect URI: %v", err)
		json.NewEncoder(w).Encode(VerifyResponse{Error: "internal error"})
		return
	}

	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if challenge.State != "" {
		q.Set("state", challenge.State)
	}
	redirectURL.RawQuery = q.Encode()

	json.NewEncoder(w).Encode(VerifyResponse{
		Success:     true,
		RedirectURL: redirectURL.String(),
	})
}
