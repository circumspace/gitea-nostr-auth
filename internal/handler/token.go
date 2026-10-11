package handler

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
)

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "invalid_request",
			ErrorDesc: "failed to parse form",
		})
		return
	}

	// Extract credentials (support both Basic auth and form params)
	clientID, clientSecret := extractClientCredentials(r)

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	// Override client credentials from form if provided
	if formClientID := r.FormValue("client_id"); formClientID != "" {
		clientID = formClientID
	}
	if formClientSecret := r.FormValue("client_secret"); formClientSecret != "" {
		clientSecret = formClientSecret
	}

	// Validate grant type
	if grantType != "authorization_code" {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "unsupported_grant_type",
			ErrorDesc: "only authorization_code is supported",
		})
		return
	}

	// Validate client
	client := h.cfg.GetClient(clientID)
	if client == nil {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "invalid_client",
			ErrorDesc: "unknown client_id",
		})
		return
	}

	// Verify client secret
	if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "invalid_client",
			ErrorDesc: "invalid client_secret",
		})
		return
	}

	// Look up authorization code
	authCode, err := h.store.GetAuthCode(code)
	if err != nil || authCode == nil {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "invalid_grant",
			ErrorDesc: "invalid or expired authorization code",
		})
		return
	}

	// Verify code belongs to this client
	if authCode.ClientID != clientID {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "invalid_grant",
			ErrorDesc: "code was not issued to this client",
		})
		return
	}

	// Verify redirect URI matches
	if authCode.RedirectURI != redirectURI {
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "invalid_grant",
			ErrorDesc: "redirect_uri mismatch",
		})
		return
	}

	// Delete auth code (single use)
	h.store.DeleteAuthCode(code)

	// Create access token
	accessToken, err := h.store.CreateAccessToken(authCode.Pubkey, clientID)
	if err != nil {
		log.Printf("failed to create access token: %v", err)
		json.NewEncoder(w).Encode(TokenResponse{
			Error:     "server_error",
			ErrorDesc: "failed to create token",
		})
		return
	}

	// Generate ID token (simple JWT-like structure for OIDC compatibility)
	idToken := generateIDToken(h.cfg.Server.BaseURL, clientID, authCode.Pubkey)

	expiresIn := int(time.Until(accessToken.ExpiresAt).Seconds())

	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken.Token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		IDToken:     idToken,
	})
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// Try Basic auth header first
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}
	}
	return "", ""
}

// generateIDToken creates a simple ID token
// In production, this should be a properly signed JWT
func generateIDToken(issuer, audience, subject string) string {
	// Create a simple base64-encoded JSON token
	// In production, use proper JWT signing
	header := `{"alg":"none","typ":"JWT"}`

	now := time.Now()
	payload := map[string]interface{}{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"preferred_username": nostr.PubkeyToNpub(subject),
	}

	payloadBytes, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Unsigned token (alg: none)
	return headerB64 + "." + payloadB64 + "."
}
