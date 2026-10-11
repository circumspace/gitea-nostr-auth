package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
)

// UserInfoResponse is the /userinfo response. preferred_username, nickname
// and email are derived from the public key only, so the relying party can
// never be steered into matching an existing account by profile data.
type UserInfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified"`
	Picture           string `json:"picture,omitempty"`
	Npub              string `json:"npub,omitempty"`
}

type errorResponse struct {
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description,omitempty"`
}

// profileLookupTimeout bounds how long /userinfo waits for relays.
const profileLookupTimeout = 8 * time.Second

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	noStore(w)

	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "invalid_token", ErrorDesc: "missing or invalid Authorization header"})
		return
	}

	accessToken, err := h.store.GetAccessToken(strings.TrimSpace(token))
	if err != nil || accessToken == nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "invalid_token", ErrorDesc: "token is invalid or expired"})
		return
	}

	resp, err := h.userInfoFor(r.Context(), accessToken.Pubkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "server_error"})
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) userInfoFor(ctx context.Context, pubkey string) (*UserInfoResponse, error) {
	username, err := nostr.Username(pubkey)
	if err != nil {
		return nil, err
	}
	email, err := nostr.PlaceholderEmail(pubkey, h.cfg.Nostr.EmailDomain)
	if err != nil {
		return nil, err
	}
	npub := nostr.PubkeyToNpub(pubkey)
	resp := &UserInfoResponse{
		Sub:               pubkey,
		PreferredUsername: username,
		Nickname:          username,
		Email:             email,
		EmailVerified:     false,
		Npub:              npub,
		Name:              nostr.TruncateNpub(npub),
	}

	if h.fetcher != nil {
		ctx, cancel := context.WithTimeout(ctx, profileLookupTimeout)
		defer cancel()
		if profile := h.fetcher.FetchProfile(ctx, pubkey); profile != nil {
			if name := nostr.SanitizeDisplayName(profile.GetDisplayName()); name != "" {
				resp.Name = name
			}
			if h.cfg.Nostr.PictureEnabled() {
				resp.Picture = nostr.SafePictureURL(profile.Picture)
			}
		}
	}
	return resp, nil
}
