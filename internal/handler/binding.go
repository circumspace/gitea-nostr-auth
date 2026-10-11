package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"regexp"

	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
)

var bindingValueRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// bindingCookieName uses the __Host- prefix over https, which pins the
// cookie to this exact host, path "/" and Secure.
func (h *Handler) bindingCookieName() string {
	if h.cfg.Server.IsHTTPS() {
		return "__Host-nostr-auth-binding"
	}
	return "nostr-auth-binding"
}

// browserBinding returns the browser binding value, reusing the existing
// cookie (so several tabs can log in concurrently) or setting a new one.
// The challenge stores only its SHA-256 hash, and /verify requires the
// cookie, so a challenge can only be completed by the browser that
// requested it.
func (h *Handler) browserBinding(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(h.bindingCookieName()); err == nil && bindingValueRE.MatchString(c.Value) {
		h.setBindingCookie(w, c.Value)
		return c.Value, nil
	}
	v, err := oauth2.GenerateToken(32)
	if err != nil {
		return "", err
	}
	h.setBindingCookie(w, v)
	return v, nil
}

func (h *Handler) setBindingCookie(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.bindingCookieName(),
		Value:    v,
		Path:     "/",
		MaxAge:   int(h.cfg.Nostr.ChallengeTTL.Seconds()) + 60,
		HttpOnly: true,
		Secure:   h.cfg.Server.IsHTTPS(),
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearBindingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.bindingCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Server.IsHTTPS(),
		SameSite: http.SameSiteStrictMode,
	})
}

func hashBinding(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// bindingMatches checks the request's binding cookie against the hash stored
// with the challenge, in constant time.
func (h *Handler) bindingMatches(r *http.Request, wantHash string) bool {
	c, err := r.Cookie(h.bindingCookieName())
	if err != nil || !bindingValueRE.MatchString(c.Value) || wantHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashBinding(c.Value)), []byte(wantHash)) == 1
}
