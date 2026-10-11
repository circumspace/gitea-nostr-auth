package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
	"rsc.io/qr"

	"github.com/circumspace/gitea-nostr-auth/internal/nip46"
)

// remoteSignerWait bounds one long poll of /nip46/wait; it stays below the
// server's WriteTimeout.
const remoteSignerWait = 20 * time.Second

type remoteSignerStartRequest struct {
	Challenge string `json:"challenge"`
}

type remoteSignerStartResponse struct {
	Session   string `json:"session"`
	URI       string `json:"uri"`
	QR        string `json:"qr"`
	ExpiresIn int    `json:"expires_in"`
}

type remoteSignerWaitRequest struct {
	Session string `json:"session"`
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeVerify(w, http.StatusUnsupportedMediaType, VerifyResponse{Error: "content type must be application/json"})
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: "invalid JSON"})
		return false
	}
	return true
}

// loginEventTemplate is the unsigned login event for a challenge. The login
// page builds the same event for NIP-07 extensions.
func (h *Handler) loginEventTemplate(challenge, redirectURI string) gonostr.Event {
	return gonostr.Event{
		Kind: KindHTTPAuth,
		Tags: gonostr.Tags{
			{"u", h.verifyURL()},
			{"method", http.MethodPost},
			{"challenge", challenge},
		},
		Content: h.signingStatement(redirectURI),
	}
}

// RemoteSignerStart begins a NIP-46 login for a challenge that was issued to
// this browser and returns the nostrconnect:// URI for the signer app.
func (h *Handler) RemoteSignerStart(w http.ResponseWriter, r *http.Request) {
	var req remoteSignerStartRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	challenge, err := h.store.GetChallenge(req.Challenge)
	if err != nil || challenge == nil {
		writeVerify(w, http.StatusBadRequest, VerifyResponse{Error: "invalid or expired challenge"})
		return
	}
	if !h.bindingMatches(r, challenge.BindingHash) {
		writeVerify(w, http.StatusForbidden, VerifyResponse{Error: "challenge was issued to a different browser"})
		return
	}

	expires := h.now().Add(h.cfg.Nostr.NIP46.Timeout)
	if challenge.ExpiresAt.Before(expires) {
		expires = challenge.ExpiresAt
	}
	tmpl := h.loginEventTemplate(challenge.Nonce, challenge.RedirectURI)
	sess, err := h.remoteSigner.Start(challenge.Nonce, challenge.BindingHash, tmpl, expires)
	switch {
	case errors.Is(err, nip46.ErrCapacity):
		writeVerify(w, http.StatusServiceUnavailable, VerifyResponse{Error: err.Error()})
		return
	case errors.Is(err, nip46.ErrInUse):
		writeVerify(w, http.StatusConflict, VerifyResponse{Error: err.Error()})
		return
	case err != nil:
		log.Printf("nip46: start: %v", err)
		writeVerify(w, http.StatusInternalServerError, VerifyResponse{Error: "internal error"})
		return
	}

	code, err := qr.Encode(sess.URI, qr.M)
	if err != nil {
		log.Printf("nip46: qr: %v", err)
		writeVerify(w, http.StatusInternalServerError, VerifyResponse{Error: "internal error"})
		return
	}
	code.Scale = 6
	_ = json.NewEncoder(w).Encode(remoteSignerStartResponse{
		Session:   sess.ID,
		URI:       sess.URI,
		QR:        "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()),
		ExpiresIn: int(time.Until(sess.ExpiresAt).Seconds()),
	})
}

// RemoteSignerWait long-polls a NIP-46 login. Once the signer has returned
// the signed event, it completes the login exactly like /verify.
func (h *Handler) RemoteSignerWait(w http.ResponseWriter, r *http.Request) {
	var req remoteSignerWaitRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	sess := h.remoteSigner.Get(req.Session)
	if sess == nil {
		writeVerify(w, http.StatusNotFound, VerifyResponse{Error: "unknown or expired remote signer session"})
		return
	}
	if !h.bindingMatches(r, sess.BindingHash) {
		writeVerify(w, http.StatusForbidden, VerifyResponse{Error: "session belongs to a different browser"})
		return
	}

	timer := time.NewTimer(remoteSignerWait)
	defer timer.Stop()
	select {
	case <-sess.Done():
	case <-timer.C:
		writeVerify(w, http.StatusOK, VerifyResponse{Pending: true})
		return
	case <-r.Context().Done():
		return
	}

	ev, err := sess.Result()
	h.remoteSigner.Remove(sess.ID)
	if err != nil {
		writeVerify(w, http.StatusBadGateway, VerifyResponse{Error: err.Error()})
		return
	}
	h.completeLogin(w, r, ev)
}
