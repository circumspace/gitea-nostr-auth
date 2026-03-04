package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/mlekudev/gitea-nostr-auth/internal/nostr"
)

type UserInfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Website           string `json:"website,omitempty"`
	Error             string `json:"error,omitempty"`
	ErrorDesc         string `json:"error_description,omitempty"`
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Extract Bearer token
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(UserInfoResponse{
			Error:     "invalid_token",
			ErrorDesc: "missing or invalid Authorization header",
		})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Look up access token
	accessToken, err := h.store.GetAccessToken(token)
	if err != nil || accessToken == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(UserInfoResponse{
			Error:     "invalid_token",
			ErrorDesc: "token is invalid or expired",
		})
		return
	}

	pubkey := accessToken.Pubkey
	npub := nostr.PubkeyToNpub(pubkey)

	// Fetch profile from relays (this also fetches relay list first)
	log.Printf("Fetching profile for %s from relays...", nostr.TruncateNpub(npub))
	profile := h.fetcher.FetchProfile(r.Context(), pubkey)

	// Build response with profile data or fallbacks
	response := UserInfoResponse{
		Sub: pubkey,
	}

	if profile != nil {
		log.Printf("Got profile for %s: name=%s, nip05=%s", nostr.TruncateNpub(npub), profile.Name, profile.Nip05)

		// Use profile data
		response.Name = profile.GetDisplayName()
		response.PreferredUsername = profile.GetUsername()
		response.Picture = profile.Picture
		response.Website = profile.Website
		response.Profile = profile.About

		// Use NIP-05 as email if available (it's verified in the Nostr sense)
		if profile.Nip05 != "" {
			// NIP-05 format: name@domain.com or _@domain.com
			response.Email = profile.Nip05
			response.EmailVerified = false // We haven't verified it ourselves
		} else {
			response.Email = nostr.GeneratePlaceholderEmail(pubkey)
		}
	} else {
		log.Printf("No profile found for %s, using defaults", nostr.TruncateNpub(npub))

		// Fallback to generated values
		response.PreferredUsername = nostr.GenerateUsername(pubkey)
		response.Name = nostr.TruncateNpub(npub)
		response.Email = nostr.GeneratePlaceholderEmail(pubkey)
	}

	json.NewEncoder(w).Encode(response)
}
