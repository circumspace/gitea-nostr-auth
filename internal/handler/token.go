package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
)

type TokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// IDTokenClaims are the claims of an issued ID token. Only values derived
// from the authenticated public key are included; profile data is served by
// /userinfo and is display-only.
type IDTokenClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	AuthorizedParty   string `json:"azp"`
	ExpiresAt         int64  `json:"exp"`
	IssuedAt          int64  `json:"iat"`
	AuthTime          int64  `json:"auth_time"`
	Nonce             string `json:"nonce,omitempty"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
}

var pkceVerifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token", charset="UTF-8"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(TokenResponse{Error: code, ErrorDesc: desc})
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	noStore(w)

	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}
	// Parameters must come from the form body, not the query string.
	for _, k := range []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"} {
		if len(r.PostForm[k]) > 1 {
			tokenError(w, http.StatusBadRequest, "invalid_request", "duplicate parameter "+k)
			return
		}
	}

	clientID, clientSecret, usedBasic, err := clientCredentials(r)
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	authFailStatus := http.StatusBadRequest
	if usedBasic {
		authFailStatus = http.StatusUnauthorized
	}
	client := h.cfg.GetClient(clientID)
	if client == nil || client.ClientSecret == "" ||
		subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		tokenError(w, authFailStatus, "invalid_client", "client authentication failed")
		return
	}

	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	code := r.PostForm.Get("code")
	if code == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing code")
		return
	}

	// Atomic single use. A second presentation revokes the issued token.
	authCode, err := h.store.ConsumeAuthCode(code)
	if errors.Is(err, oauth2.ErrCodeReused) {
		log.Printf("authorization code reuse detected for client %s; issued token revoked", clientID)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")
		return
	}
	if err != nil || authCode == nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if authCode.ClientID != clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code was not issued to this client")
		return
	}
	if authCode.RedirectURI != r.PostForm.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if err := checkPKCE(authCode.CodeChallenge, r.PostForm.Get("code_verifier")); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	accessToken, err := h.store.CreateAccessToken(authCode.Pubkey, clientID, h.cfg.OAuth2.AccessTokenTTL)
	if err != nil {
		log.Printf("failed to create access token: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to create token")
		return
	}
	h.store.BindToken(code, accessToken.Token)

	idToken, err := h.issueIDToken(clientID, authCode)
	if err != nil {
		h.store.RevokeAccessToken(accessToken.Token)
		log.Printf("failed to sign id token: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to create token")
		return
	}

	_ = json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.cfg.OAuth2.AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       "openid profile email",
	})
}

func (h *Handler) issueIDToken(clientID string, ac *oauth2.AuthCode) (string, error) {
	username, err := nostr.Username(ac.Pubkey)
	if err != nil {
		return "", err
	}
	email, err := nostr.PlaceholderEmail(ac.Pubkey, h.cfg.Nostr.EmailDomain)
	if err != nil {
		return "", err
	}
	now := h.now()
	return h.signer.Sign(IDTokenClaims{
		Issuer:            h.cfg.Server.BaseURL,
		Subject:           ac.Pubkey,
		Audience:          clientID,
		AuthorizedParty:   clientID,
		ExpiresAt:         now.Add(h.cfg.OAuth2.IDTokenTTL).Unix(),
		IssuedAt:          now.Unix(),
		AuthTime:          ac.AuthTime.Unix(),
		Nonce:             ac.Nonce,
		PreferredUsername: username,
		Nickname:          username,
		Email:             email,
		EmailVerified:     false,
	})
}

// checkPKCE verifies an S256 code_verifier against the stored challenge. A
// verifier without a stored challenge is rejected (downgrade protection).
func checkPKCE(challenge, verifier string) error {
	if challenge == "" {
		if verifier != "" {
			return errors.New("code_verifier sent but no code_challenge was used")
		}
		return nil
	}
	if !pkceVerifierRE.MatchString(verifier) {
		return errors.New("missing or malformed code_verifier")
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return errors.New("code_verifier does not match code_challenge")
	}
	return nil
}

// clientCredentials extracts client credentials from HTTP Basic auth
// (RFC 6749 2.3.1, form-urlencoded values) or the form body. Using both
// methods at once is rejected.
func clientCredentials(r *http.Request) (id, secret string, usedBasic bool, err error) {
	formID := r.PostForm.Get("client_id")
	formSecret := r.PostForm.Get("client_secret")

	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		scheme, payload, ok := strings.Cut(authHeader, " ")
		if !ok || !strings.EqualFold(scheme, "Basic") {
			return "", "", false, errors.New("unsupported Authorization scheme")
		}
		decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
		if derr != nil {
			return "", "", true, errors.New("malformed Basic credentials")
		}
		rawID, rawSecret, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return "", "", true, errors.New("malformed Basic credentials")
		}
		if id, err = url.QueryUnescape(rawID); err != nil {
			return "", "", true, errors.New("malformed Basic credentials")
		}
		if secret, err = url.QueryUnescape(rawSecret); err != nil {
			return "", "", true, errors.New("malformed Basic credentials")
		}
		if formSecret != "" {
			return "", "", true, errors.New("multiple client authentication methods used")
		}
		if formID != "" && formID != id {
			return "", "", true, errors.New("client_id mismatch")
		}
		return id, secret, true, nil
	}
	return formID, formSecret, false, nil
}
