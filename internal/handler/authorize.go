package handler

import (
	"html/template"
	"log"
	"net/http"
)

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login with Nostr</title>
    <style>
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

        <div id="no-extension" class="no-extension hidden">
            <p>No Nostr extension detected. Please install one of these:</p>
            <ul class="extension-list">
                <li><a href="https://getalby.com" target="_blank">Alby</a></li>
                <li><a href="https://github.com/nickytonline/nos2x" target="_blank">nos2x</a></li>
                <li><a href="https://github.com/nickytonline/flamingo" target="_blank">Flamingo</a></li>
            </ul>
        </div>

        <div id="login-section">
            <button id="login-btn" disabled>Checking for extension...</button>
            <div id="status" class="status hidden"></div>
        </div>
    </div>

    <script>
        const challenge = "{{.Challenge}}";
        const verifyURL = "{{.VerifyURL}}";

        const loginBtn = document.getElementById('login-btn');
        const statusDiv = document.getElementById('status');
        const noExtensionDiv = document.getElementById('no-extension');
        const loginSection = document.getElementById('login-section');

        function showStatus(message, type) {
            statusDiv.textContent = message;
            statusDiv.className = 'status ' + type;
            statusDiv.classList.remove('hidden');
        }

        function hideStatus() {
            statusDiv.classList.add('hidden');
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
            loginBtn.disabled = true;
            loginBtn.textContent = 'Signing...';
            hideStatus();

            try {
                // Get public key
                const pubkey = await window.nostr.getPublicKey();
                showStatus('Got public key, signing challenge...', 'info');

                // Create event to sign (NIP-98 style)
                const event = {
                    kind: 27235,
                    created_at: Math.floor(Date.now() / 1000),
                    tags: [
                        ['u', window.location.href],
                        ['method', 'GET'],
                        ['challenge', challenge]
                    ],
                    content: ''
                };

                // Sign the event
                const signedEvent = await window.nostr.signEvent(event);
                showStatus('Signed! Verifying with server...', 'info');

                // Submit to server
                const response = await fetch(verifyURL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(signedEvent)
                });

                const result = await response.json();

                if (result.redirect_url) {
                    showStatus('Success! Redirecting...', 'success');
                    window.location.href = result.redirect_url;
                } else if (result.error) {
                    showStatus('Error: ' + result.error, 'error');
                    loginBtn.disabled = false;
                    loginBtn.textContent = 'Try again';
                }
            } catch (err) {
                console.error('Login error:', err);
                showStatus('Error: ' + err.message, 'error');
                loginBtn.disabled = false;
                loginBtn.textContent = 'Try again';
            }
        }

        loginBtn.addEventListener('click', login);
        checkExtension();
    </script>
</body>
</html>`

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Extract OAuth2 parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	responseType := r.URL.Query().Get("response_type")

	// Validate required parameters
	if clientID == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		http.Error(w, "unsupported response_type, must be 'code'", http.StatusBadRequest)
		return
	}

	// Validate client and redirect URI
	if !h.cfg.ValidateRedirectURI(clientID, redirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}

	// Create challenge
	challenge, err := h.store.CreateChallenge(clientID, state, redirectURI, h.cfg.Nostr.ChallengeTTL)
	if err != nil {
		log.Printf("failed to create challenge: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Render login page
	tmpl, err := template.New("login").Parse(loginPageHTML)
	if err != nil {
		log.Printf("failed to parse template: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Challenge string
		VerifyURL string
	}{
		Challenge: challenge.Nonce,
		VerifyURL: h.cfg.Server.BaseURL + "/verify",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("failed to execute template: %v", err)
	}
}
