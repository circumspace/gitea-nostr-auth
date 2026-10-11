package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
)

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login with Nostr</title>
    <style nonce="{{.CSPNonce}}">
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 {
            color: #fff;
            margin-bottom: 10px;
            font-size: 24px;
        }
        .subtitle {
            color: rgba(255, 255, 255, 0.6);
            margin-bottom: 30px;
            font-size: 14px;
        }
        .nostr-logo {
            font-size: 64px;
            margin-bottom: 20px;
        }
        button {
            background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);
            color: white;
            border: none;
            padding: 16px 32px;
            font-size: 16px;
            border-radius: 12px;
            cursor: pointer;
            width: 100%;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 10px 40px rgba(139, 92, 246, 0.3);
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .status {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            font-size: 14px;
        }
        .status.error {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .status.success {
            background: rgba(34, 197, 94, 0.2);
            color: #86efac;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }
        .status.info {
            background: rgba(59, 130, 246, 0.2);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }
        .hidden {
            display: none;
        }
        .no-extension {
            color: rgba(255, 255, 255, 0.8);
        }
        .no-extension a {
            color: #8b5cf6;
            text-decoration: none;
        }
        .no-extension a:hover {
            text-decoration: underline;
        }
        .extension-list {
            margin-top: 15px;
            text-align: left;
            padding-left: 20px;
        }
        .extension-list li {
            margin: 8px 0;
            color: rgba(255, 255, 255, 0.7);
        }
        .target {
            color: rgba(255, 255, 255, 0.8);
            font-size: 13px;
            margin-bottom: 24px;
            word-break: break-all;
        }
        .pubkey {
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            background: rgba(0, 0, 0, 0.3);
            padding: 8px;
            border-radius: 6px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="nostr-logo">&#x1F5DD;</div>
        <h1>Login with Nostr</h1>
        <p class="subtitle">Sign in using your Nostr identity</p>
        <p class="target">Signing in to <strong>{{.ClientHost}}</strong> via <strong>{{.IssuerHost}}</strong>.<br>Your extension will ask you to sign &ldquo;{{.Statement}}&rdquo;. Only approve that on this page.</p>

        <div id="no-extension" class="no-extension hidden">
            <p>No Nostr extension detected. Please install one of these:</p>
            <ul class="extension-list">
                <li><a href="https://getalby.com" target="_blank" rel="noopener noreferrer">Alby</a></li>
                <li><a href="https://github.com/fiatjaf/nos2x" target="_blank" rel="noopener noreferrer">nos2x</a></li>
            </ul>
        </div>

        <div id="login-section">
            <button id="login-btn" disabled>Checking for extension...</button>
            <div id="status" class="status hidden"></div>
        </div>
    </div>

    <script nonce="{{.CSPNonce}}">
        const challenge = {{.Challenge}};
        const verifyURL = {{.VerifyURL}};
        const statement = {{.Statement}};

        const loginBtn = document.getElementById('login-btn');
        const statusDiv = document.getElementById('status');
        const noExtensionDiv = document.getElementById('no-extension');
        let used = false;

        function showStatus(message, type) {
            statusDiv.textContent = message;
            statusDiv.className = 'status ' + type;
            statusDiv.classList.remove('hidden');
        }

        function hideStatus() {
            statusDiv.classList.add('hidden');
        }

        function fail(message) {
            // A challenge is single use: retrying needs a fresh page.
            showStatus('Error: ' + message, 'error');
            loginBtn.disabled = false;
            loginBtn.textContent = 'Try again';
            used = true;
        }

        async function checkExtension() {
            // Wait a bit for extension to inject
            await new Promise(resolve => setTimeout(resolve, 100));

            if (typeof window.nostr === 'undefined') {
                noExtensionDiv.classList.remove('hidden');
                loginBtn.textContent = 'No extension found';
                return false;
            }

            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign in with Nostr';
            return true;
        }

        async function login() {
            if (used) {
                window.location.reload();
                return;
            }
            loginBtn.disabled = true;
            loginBtn.textContent = 'Signing...';
            hideStatus();

            try {
                // NIP-98 style event bound to this server's /verify endpoint
                const event = {
                    kind: 27235,
                    created_at: Math.floor(Date.now() / 1000),
                    tags: [
                        ['u', verifyURL],
                        ['method', 'POST'],
                        ['challenge', challenge]
                    ],
                    content: statement
                };

                const signedEvent = await window.nostr.signEvent(event);
                showStatus('Signed! Verifying with server...', 'info');

                const response = await fetch(verifyURL, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(signedEvent)
                });

                const result = await response.json();

                if (response.ok && result.redirect_url) {
                    showStatus('Success! Redirecting...', 'success');
                    window.location.assign(result.redirect_url);
                } else {
                    fail(result.error || ('HTTP ' + response.status));
                }
            } catch (err) {
                console.error('Login error:', err);
                fail(err && err.message ? err.message : String(err));
            }
        }

        loginBtn.addEventListener('click', login);
        checkExtension();
    </script>
</body>
</html>`

// Limits on client-supplied parameters that are stored with a challenge.
const (
	maxStateLen     = 1024
	maxNonceLen     = 512
	pkceChallengeRE = `^[A-Za-z0-9_-]{43}$` // base64url(SHA-256), no padding
)

var pkceChallengeMatcher = regexp.MustCompile(pkceChallengeRE)

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	// Until client_id and redirect_uri are validated, errors are shown to
	// the user and never redirected (no open redirect).
	if clientID == "" || redirectURI == "" {
		http.Error(w, "missing client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if !h.cfg.ValidateRedirectURI(clientID, redirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "response_type", "scope", "code_challenge", "code_challenge_method"} {
		if len(q[k]) > 1 {
			http.Error(w, "duplicate parameter "+k, http.StatusBadRequest)
			return
		}
	}
	client := h.cfg.GetClient(clientID)
	state := q.Get("state")

	if len(state) > maxStateLen {
		http.Error(w, "state too long", http.StatusBadRequest)
		return
	}
	if q.Get("request") != "" || q.Get("request_uri") != "" {
		redirectError(w, r, redirectURI, state, "request_not_supported", "request objects are not supported")
		return
	}
	if q.Get("response_type") != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type", "response_type must be 'code'")
		return
	}
	if !slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		redirectError(w, r, redirectURI, state, "invalid_scope", "scope must include 'openid'")
		return
	}
	if rm := q.Get("response_mode"); rm != "" && rm != "query" {
		redirectError(w, r, redirectURI, state, "invalid_request", "only response_mode=query is supported")
		return
	}
	nonce := q.Get("nonce")
	if len(nonce) > maxNonceLen {
		redirectError(w, r, redirectURI, state, "invalid_request", "nonce too long")
		return
	}
	codeChallenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if codeChallenge != "" {
		if method != "S256" {
			redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge_method must be S256")
			return
		}
		if !pkceChallengeMatcher.MatchString(codeChallenge) {
			redirectError(w, r, redirectURI, state, "invalid_request", "malformed code_challenge")
			return
		}
	} else if method != "" {
		redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge_method without code_challenge")
		return
	} else if client.RequirePKCE {
		redirectError(w, r, redirectURI, state, "invalid_request", "PKCE (S256) is required for this client")
		return
	}
	if q.Get("prompt") == "none" {
		// There is no session here; every login needs a fresh signature.
		redirectError(w, r, redirectURI, state, "login_required", "interactive login required")
		return
	}

	binding, err := h.browserBinding(w, r)
	if err != nil {
		log.Printf("failed to create browser binding: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	req := oauth2.AuthRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
	}
	challenge, err := h.store.CreateChallenge(req, hashBinding(binding), h.cfg.Nostr.ChallengeTTL)
	if err != nil {
		if errors.Is(err, oauth2.ErrCapacity) {
			http.Error(w, "server busy, try again later", http.StatusServiceUnavailable)
			return
		}
		log.Printf("failed to create challenge: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cspNonce, err := oauth2.GenerateToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Challenge  string
		VerifyURL  string
		Statement  string
		ClientHost string
		IssuerHost string
		CSPNonce   string
	}{
		Challenge:  challenge.Nonce,
		VerifyURL:  h.verifyURL(),
		Statement:  h.signingStatement(redirectURI),
		ClientHost: hostOf(redirectURI),
		IssuerHost: hostOf(h.cfg.Server.BaseURL),
		CSPNonce:   cspNonce,
	}

	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; img-src 'self'; "+
			"base-uri 'none'; form-action 'none'; frame-ancestors 'none'", cspNonce, cspNonce))
	if err := h.loginTmpl.Execute(w, data); err != nil {
		log.Printf("failed to execute template: %v", err)
	}
}

func (h *Handler) verifyURL() string { return h.cfg.Server.BaseURL + "/verify" }

// signingStatement is the human-readable content of the event the user
// signs. It names both the relying party and this server so that a signing
// prompt shown by the extension makes the purpose visible, and the server
// requires it verbatim.
func (h *Handler) signingStatement(redirectURI string) string {
	return fmt.Sprintf("Sign in to %s via %s", hostOf(redirectURI), hostOf(h.cfg.Server.BaseURL))
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// redirectError sends an OAuth2 error response to a validated redirect_uri.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
