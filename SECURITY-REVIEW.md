# Security review: gitea-nostr-auth

- Reviewed revision: `c4dfb36` (upstream `mlekudev/gitea-nostr-auth`, the only commit, 2026-03-04)
- Review date: 2026-10-11
- Scope: every file in the repository (`cmd/`, `internal/`, `pkg/`, `Dockerfile`,
  `config.example.yaml`, `README.md`, `go.mod`/`go.sum`, `.claude/commands/release.md`),
  plus the parts of the `next.orly.dev` dependency on the security path (event
  parsing/verification and the websocket relay client).
- Target deployment: Kubernetes, next to a Gitea instance (Forgejo secondary),
  tailnet-only for now. The relying party is Gitea's "OpenID Connect" OAuth2
  authentication source (goth `openidConnect` provider).

Line numbers refer to the reviewed revision `c4dfb36`.

## Summary

| ID | Severity | Title |
|----|----------|-------|
| C-1 | Critical | Signature check trusts the attacker-supplied event `id`: anyone can log in as any Nostr user who has ever published an event |
| C-2 | Critical | Username and email come from unverified kind-0 profile data (`nip05`, `name`); with Gitea `ACCOUNT_LINKING=auto` this takes over existing accounts |
| H-1 | High | ID tokens are unsigned (`alg: none`), while discovery advertises RS256 and JWKS is empty |
| H-2 | High | Fallback username / placeholder email use a 35-bit npub prefix that can be ground to collide |
| H-3 | High | SSRF and amplification through user-controlled NIP-65 relay URLs |
| H-4 | High | Challenge not bound to origin, endpoint or browser; wildcard CORS with credentials |
| M-1 | Medium | Authorization code and challenge single-use checks are not atomic (TOCTOU) |
| M-2 | Medium | No PKCE support |
| M-3 | Medium | OIDC `nonce` ignored |
| M-4 | Medium | Empty or published placeholder client secret accepted |
| M-5 | Medium | No HTTP server timeouts |
| M-6 | Medium | Unbounded memory: challenge map, profile/relay caches, request bodies; no rate limiting |
| M-7 | Medium | Attacker-controlled `picture` URL fed to Gitea's avatar fetcher |
| M-8 | Medium | Supply chain: `next.orly.dev` replaced with a pseudo-version from a self-hosted forge |
| M-9 | Medium | Dockerfile cannot build, runs as root, unpinned images, bakes in a placeholder secret |
| L-1 | Low | Token endpoint does not follow RFC 6749 error/caching semantics; mixed client-auth handling |
| L-2 | Low | Login page lacks CSP / frame-ancestors / Referrer-Policy; template re-parsed on every request |
| L-3 | Low | `middleware.RealIP` trusts `X-Forwarded-For` from any client (GO-2026-5775 / GO-2026-5777) |
| L-4 | Low | Go toolchain go1.27.1 has reachable stdlib vulnerabilities (fixed in go1.27.2) |
| L-5 | Low | Profile cache: negative results cached for 24 h, profile rollback by relays |
| L-6 | Low | Wrong claim semantics: `profile` holds free text, `email_verified=false` is omitted |
| L-7 | Low | Config: environment parse errors ignored; `http://localhost` issuer default; `openid` scope not required |
| L-8 | Low | Logging: full query strings and profile data in logs |
| L-9 | Low | Access tokens: 24 h lifetime, no revocation, stored in plain form |
| I-1 | Info | `.claude/commands/release.md` automates commit, tag and `git push origin main` |

Things that are already correct: `redirect_uri` is exact-string matched against a
per-client allowlist (`internal/config/config.go:135-146`) and re-checked at the
token endpoint (`internal/handler/token.go:106-113`); the code is bound to the
client (`token.go:97-104`); challenges, codes and tokens are 256-bit values from
`crypto/rand` (`internal/oauth2/store.go:99-105`); the client secret is compared in
constant time (`token.go:79`); `html/template` escapes the values inserted into the
login page script; `http.Error` responses are `text/plain` with `nosniff`.

## Tool results (before changes)

- `go vet ./...`: no findings.
- `staticcheck ./...` (2026.2.1): no findings. (The preinstalled 2025 build could
  not load go1.27 export data; reinstalled `@latest`.)
- `govulncheck ./...` (go1.27.1): 11 reachable vulnerabilities:
  - stdlib, all fixed in go1.27.2: GO-2026-6617, GO-2026-6612, GO-2026-6611,
    GO-2026-6603 (HTTP/2 server; only reachable with TLS/h2c, which this server
    does not enable), GO-2026-6613 (HTTP/1 CONNECT desync), GO-2026-6608
    (net/textproto MIME header memory limit), GO-2026-6607 (crypto/tls ECH),
    GO-2026-6600, GO-2026-6599 (html/template escaping);
  - `github.com/go-chi/chi/v5@v5.1.0`: GO-2026-5775, GO-2026-5777 (RealIP
    `X-Forwarded-For` spoofing), fixed in v5.3.0.
  - Not reachable: 4 more stdlib issues in imported packages, and GO-2026-5024 in
    `golang.org/x/sys@v0.41.0`.

## Findings

### C-1 (Critical): signature check trusts the attacker-supplied event `id`

**Where:** `internal/handler/verify.go:31-60` calls `event.E.Unmarshal` and then
`ev.Verify()`. In `next.orly.dev` (`pkg/nostr/encoders/event/event.go:265-280`)
`Unmarshal` copies the `id` field from the JSON unchanged, and `Verify`
(`pkg/nostr/encoders/event/signatures.go:35-58`) checks the Schnorr signature
against that claimed `id`. It recomputes the canonical hash only when the signature
does **not** match. A valid `(id, sig)` pair taken from any other event passes, no
matter what the kind, tags, content or timestamp are.

**Exploit:** take any public event by the victim from any relay (a kind-1 note, a
reaction, anything). Ask `/authorize` for a challenge in your own browser. POST to
`/verify`:

```json
{"id":"<victim note id>","pubkey":"<victim pubkey>","created_at":<now>,
 "kind":27235,"tags":[["challenge","<your challenge>"]],"content":"",
 "sig":"<victim note sig>"}
```

The server returns `redirect_url` with a valid code for the victim's pubkey. Gitea
logs you in as the victim, or auto-registers a new account bound to the victim's
`sub`. This was confirmed with a proof-of-concept test against the reviewed code.
The response was `{"success":true,"redirect_url":"https://g/cb?code=…&state=st"}`.
The relay client in the same library (`pkg/nostr/ws/client.go:360-362`) uses the
same `Verify`. So a malicious relay can also forge kind-0 and kind-10002 events
for any pubkey, which feeds C-2 and H-3.

**Fix:** recompute the event id from the canonical serialisation and require it
to equal the supplied `id`. Verify the signature over the recomputed hash. The
`nbd-wtf/go-nostr` port uses `Event.CheckID()` plus `Event.CheckSignature()`.
`CheckSignature` hashes `Serialize()` and ignores the `id` field. Apply the same
checks to every event received from relays. The upstream `next.orly.dev` bug should
be reported too, because it affects that relay implementation.

### C-2 (Critical): identity claims come from unverified profile data

**Where:** `internal/handler/userinfo.go:64-81` and
`internal/nostr/relays.go:24-40`. `preferred_username` is set from the kind-0
`nip05`, or else `name` or `display_name`. `email` is set from the kind-0 `nip05`.
Any pubkey can publish any of these values. NIP-05 is never verified (no
`/.well-known/nostr.json` lookup). The values are not unique, and an event from
any relay is accepted (combined with C-1, even one forged by the relay).

**How Gitea consumes it:** goth's `openidConnect` provider maps
`nickname`→`preferred_username` to `NickName`, plus `email`, `name` and `picture`.
Userinfo claims override ID-token claims. With the default
`[oauth2_client] USERNAME = nickname`, the Gitea username comes from the
`preferred_username` claim. When auto-registration hits an existing username or
email, Gitea v28 `routers/web/auth/auth.go` (`createUserInContext`) does this:

- with `ACCOUNT_LINKING = auto`, it **links the new external identity to the
  existing user found by username, then by primary email**, and logs the attacker
  in;
- with `login` (the default), it shows a page asking for the existing account's
  password;
- with `disabled`, it shows an error.

**Exploit:** an attacker creates a fresh key and publishes kind 0 with
`{"name":"admin"}` or `{"nip05":"daniel@circum.space"}`. On an instance with
`ACCOUNT_LINKING=auto`, logging in through Nostr links the attacker's key to the
existing `admin` account, or to the account whose email is
`daniel@circum.space`. That is a full takeover. Without `auto`, the attacker can
still squat names ("first come, first served"), impersonate people through
username, full name and avatar, and block registration for the legitimate owner.
NIP-05 values like `bob@example.com` are also not valid Gitea usernames.

**Fix:** make every identifier Gitea might match on deterministic and derived from
the pubkey:

- `preferred_username` and `nickname`: a 100-bit npub prefix (see H-2);
- `email`: `<full npub>@nostr.invalid`, a reserved TLD (RFC 6761) that never
  matches a real mailbox;
- `email_verified`: always present and `false`.

Treat `name` and `picture` as untrusted display data: sanitise and length-limit
them. Document `ACCOUNT_LINKING` (never `auto`) in the README.

### H-1 (High): unsigned ID tokens

**Where:** `internal/handler/token.go:157-181` emits `{"alg":"none"}` tokens with
an empty signature. `internal/handler/discovery.go:34` advertises RS256, and
`discovery.go:67-76` serves an empty JWKS.

**Exploit:** a relying party that validates tokens (OIDC Core 3.1.3.7 requires it)
rejects every login. A relying party that does not validate (goth's
`openidConnect`, `providers/openidConnect/openidConnect.go:510-523`, only
base64-decodes the payload) gets no integrity protection beyond TLS. Any
component that reads the token outside the back channel (logs, proxies, a
future RP) can forge identities. Libraries that honour `alg: none` turn this into
trivial forgery.

**Fix:** sign ID tokens with RS256. Load the key from a PEM file mounted as a
Kubernetes secret, or generate an ephemeral key at startup. Publish the public key
in JWKS with an RFC 7638 thumbprint `kid`. Include `iss`, `sub`, `aud`, `azp`,
`exp` (short), `iat`, `auth_time`, and `nonce` when requested.

### H-2 (High): grindable fallback username and placeholder email

**Where:** `internal/nostr/pubkey.go:38-53`. `GenerateUsername` returns
`npub[:12]` (5 data characters × 5 bits = **35 bits** after the fixed `npub1`
prefix). `GeneratePlaceholderEmail` reuses the same value with `@nostr.local`.

**Exploit:** about 2^35 key generations (hours on one GPU, minutes on a rented
rig) give a key whose username and placeholder email equal a victim's. With
`ACCOUNT_LINKING=auto`, Gitea links the attacker's new `sub` to the victim's
existing account (username collision, then email collision): account takeover.
Otherwise the attacker can pre-register the victim's future username.

**Fix:** use ≥100 bits: `npub[:25]` (`npub1` + 20 characters) as the username,
which fits Gitea's 40-character limit, and the full 63-character npub as the email
local part.

### H-3 (High): SSRF and amplification through NIP-65 relay URLs

**Where:** `internal/nostr/fetcher.go:115-136` takes every `r` tag of the user's
kind-10002 event verbatim. `fetcher.go:161-167` adds every "read" relay.
`fetcher.go:267-300` dials every URL concurrently (`ws.RelayConnect`) with no
scheme, host, IP or count restrictions.

**Exploit:** an attacker publishes a relay list with
`["r","ws://10.0.0.1:6443/"]`, `["r","ws://kubernetes.default.svc/"]`,
`["r","ws://169.254.169.254/"]`, `["r","ws://100.x.y.z:…/"]` (tailnet), and
thousands more entries. Then the attacker logs in, or just lets Gitea call
`/userinfo`. The server makes HTTP Upgrade requests from inside the cluster and the
tailnet to all of them. That is blind SSRF and port scanning, and a fan-out DoS:
one login causes N outbound connections, each with a 33 MB websocket read limit
(`next.orly.dev/pkg/nostr/ws/connection.go:45`). The 24 h cache does not help an
attacker who uses fresh keys.

**Fix:**

- accept only `wss://` user relays (no userinfo, ≤ 256 characters);
- cap the user relays used to a small number (5);
- dial through a guarded `net.Dialer` whose `Control` hook rejects loopback,
  private, link-local, CGNAT/tailnet (100.64/10), multicast, unspecified,
  benchmarking and other non-global ranges *after* DNS resolution, which also
  defeats DNS rebinding;
- ignore proxy environment variables;
- set a small websocket read limit, per-relay event limits and a global
  connection semaphore.

### H-4 (High): challenge not bound to origin, endpoint or browser

**Where:** `internal/handler/verify.go:62-87` accepts any kind-27235 event that
carries a `challenge` tag. The `u` and `method` tags are not checked. The login
page itself signs `["u", window.location.href]` and `["method","GET"]`
(`internal/handler/authorize.go:193-200`) for what is actually a POST to
`/verify`. The challenge is not tied to the browser that started the flow.
`internal/handler/routes.go:22-28` enables CORS for `*` with
`AllowCredentials: true` on every endpoint, including `/verify` and `/token`.

**Exploit:** NIP-07 extensions are signing oracles. A malicious website gets a
challenge for the Gitea client from `/authorize`, with its *own* Gitea `state`.
It then asks the victim's extension to sign a kind-27235 event with that
challenge. Many extensions remember "always allow" per site, and the prompt
contains nothing that names this service. The site POSTs the event to `/verify`
directly from the victim's browser (CORS allows it and lets it read the response)
or from its server, receives the code, and completes the login to Gitea as the
victim in its own session. This is inherent to NIP-07, but nothing in the event
lets the user or the server tell a sign-in to this service apart from anything
else.

**Fix:**

- require exactly one `challenge` tag, `u` equal to the exact `/verify` URL, and
  `method` equal to `POST` (NIP-98 semantics);
- require the content to equal a server-generated human-readable statement
  ("Sign in to <host> …") that the extension prompt displays;
- bind the challenge to an `HttpOnly`, `SameSite=Strict`, `__Host-` cookie set by
  `/authorize`;
- remove CORS entirely: the login page is same-origin, and `/token` and
  `/userinfo` are server-to-server.

Residual risk (a user approving a signature on a hostile site) remains. It is
documented.

### M-1 (Medium): non-atomic single use

**Where:** `internal/handler/token.go:88-116` calls `GetAuthCode` (read lock), runs
checks, then `DeleteAuthCode`. `internal/handler/verify.go:80-87` does the same
for challenges.

**Exploit:** concurrent token requests with one intercepted code both succeed and
mint two access tokens. Concurrent `/verify` requests turn one signature into two
codes. A reused code is never detected, so tokens issued from it are not revoked
(RFC 6749 §4.1.2).

**Fix:** use an atomic `Consume*` (lookup and delete under a single write lock).
Keep a tombstone for used codes until expiry. When a used code is presented again,
revoke the access token issued for it. Also shorten the code lifetime from 10 min
to 2 min.

### M-2 (Medium): no PKCE

**Where:** `internal/handler/authorize.go:241-266` and `token.go`;
`code_challenge` is ignored.

**Exploit:** an intercepted code (logs, Referer, a compromised proxy) can be
redeemed by anyone who holds the client secret. Public clients cannot be protected
at all. Gitea's openidConnect source does not send PKCE today, so the confidential
client secret is the only protection.

**Fix:** support `S256` only (reject `plain`). Bind `code_challenge` to the code
and verify `code_verifier` in constant time. Make PKCE mandatory whenever a
challenge was sent, and per client via `require_pkce`. Advertise
`code_challenge_methods_supported`.

### M-3 (Medium): `nonce` ignored

**Where:** `authorize.go:241-266`; the ID token at `token.go:165-172` has no
`nonce`.

**Exploit:** relying parties that send `nonce` reject the token, or, if they
don't check, lose replay protection for ID tokens.

**Fix:** store `nonce` (length-limited) with the challenge and code and echo it in
the ID token.

### M-4 (Medium): empty or placeholder client secret accepted

**Where:** `internal/config/config.go:78-88` (`FromEnv` accepts a missing
`OAUTH2_CLIENT_SECRET`); `token.go:79` (`ConstantTimeCompare("", "") == 1`). The
`Dockerfile:30` copies `config.example.yaml` (secret
`change-me-to-a-secure-secret`) into the image as the default config.

**Exploit:** a deployment that forgets the secret runs with an empty or publicly
known secret. Anyone who obtains a code can then redeem it.

**Fix:** validate the config at startup. Require ≥ 32-character secrets, reject
the known placeholder, require at least one client and absolute redirect URIs
without fragments. Do not bake the example config into the image.

### M-5 (Medium): no HTTP server timeouts

**Where:** `cmd/nostr-oauth2-server/main.go:38` uses `http.ListenAndServe` with
no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` or `IdleTimeout`.

**Exploit:** slowloris-style connection exhaustion.

**Fix:** use an `http.Server` with timeouts, `MaxHeaderBytes` and graceful
shutdown on SIGTERM (Kubernetes).

### M-6 (Medium): unbounded memory, no rate limiting

**Where:**

- `internal/oauth2/store.go:107-127`: every unauthenticated `GET /authorize` with
  the public `client_id` and `redirect_uri` stores a challenge, and cleanup runs
  only once a minute;
- `internal/nostr/fetcher.go:28-29, 81-87, 180-186`: profile and relay caches are
  never evicted, and fresh keys are free;
- `internal/handler/verify.go:25`: `io.ReadAll` on an unbounded body;
- `state` has no length limit (stored per challenge).

**Exploit:** memory exhaustion by flooding `/authorize`, or by logging in with
many throwaway keys. A single multi-GB `/verify` body.

**Fix:**

- cap the number of outstanding challenges, codes and tokens;
- bound the caches with expiry sweeps;
- apply `http.MaxBytesReader` to all bodies;
- limit the lengths of `state` and `nonce`;
- recommend per-IP rate limiting at the ingress, because behind a proxy the server
  only sees the ingress IP.

### M-7 (Medium): attacker-controlled `picture`

**Where:** `internal/handler/userinfo.go:70` passes the kind-0 `picture` through
unvalidated.

**Exploit:** with Gitea `[oauth2_client] UPDATE_AVATAR = true`, Gitea fetches the
URL server-side on each login. Gitea v28 routes this through its egress security
policy, but older versions and Forgejo may not, which gives SSRF from Gitea
(`http://169.254.169.254/…`, internal services). `website` and `profile` are
also unvalidated.

**Fix:** emit `picture` only for `https://` URLs with a DNS hostname (no IP
literals, no `localhost`, no userinfo, ≤ 2048 characters). Drop
`website`/`profile`. Document `UPDATE_AVATAR`.

### M-8 (Medium): supply chain, `next.orly.dev` replace

**Where:** `go.mod:9,26`. The vanity module `next.orly.dev v0.0.0` is replaced with
`git.nostrdev.com/mleku/next.orly.dev v0.62.10-0.20260304132327-91c9990176b9`.
That is an untagged pseudo-version from a single-maintainer self-hosted forge.
It is a 47 MB monorepo (relay, database, assembly SHA-256, `purego`, etc.).

**Risk:**

- availability depends on that forge (the module is currently cached by
  proxy.golang.org, so it is pinned via the checksum DB);
- `replace` directives are ignored when the module is consumed as a dependency;
- a large transitive attack surface;
- the security-critical verification bug C-1 lives there.

**Fix:** port to `github.com/nbd-wtf/go-nostr`, the widely used library, tagged
releases on GitHub/proxy.golang.org, and remove the replace.

### M-9 (Medium): Dockerfile hygiene

**Where:** `Dockerfile:2,20,30,36`.

- `golang:1.22-alpine` cannot build a `go 1.25.3` module, because the image sets
  `GOTOOLCHAIN=local`. The image does not build.
- The runtime runs as root.
- Tags are unpinned (no digest).
- The placeholder config (M-4) is baked in.
- `-a -installsuffix cgo` is obsolete.

**Fix:**

- multi-stage build on the current Go image pinned by digest;
- `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`;
- a `gcr.io/distroless/static-debian12:nonroot` runtime pinned by digest;
- no baked config, `USER nonroot`;
- read-only root filesystem friendly.

### L-1 (Low): token endpoint semantics

**Where:** `internal/handler/token.go:36-127`.

- All errors return HTTP 200 instead of 400, and 401 for `invalid_client`
  (RFC 6749 §5.2).
- There is no `Cache-Control: no-store` / `Pragma: no-cache` (§5.1).
- Form credentials silently override Basic credentials, although a client must not
  use two methods (§2.3).
- Basic credentials are not form-urlencoded-decoded (§2.3.1).

**Fix:** implement as specified.

### L-2 (Low): login page headers

**Where:** `internal/handler/authorize.go:276-295`. There is no
`Content-Security-Policy`, no `frame-ancestors`/`X-Frame-Options` (clickjacking of
the sign-in button), no `Referrer-Policy` (the authorize URL carries `state`), and
no `Cache-Control`. The template is parsed on every request.

**Fix:**

- a strict CSP with a per-response nonce, `frame-ancestors 'none'` and
  `connect-src 'self'`;
- `Referrer-Policy: no-referrer` and `Cache-Control: no-store`;
- parse the template once.

### L-3 (Low): RealIP trusts client headers

**Where:** `internal/handler/routes.go:21`. Any client can set `X-Forwarded-For`
or `X-Real-IP` and spoof the logged address (GO-2026-5775/5777). The address is
not used for authorisation.

**Fix:** remove `RealIP`, and update chi to ≥ v5.3.0.

### L-4 (Low): toolchain vulnerabilities

The binary was built with go1.27.1. govulncheck reports the stdlib issues listed
above, fixed in go1.27.2. **Fix:** `toolchain go1.27.2` in `go.mod`, and the same
version in the Docker build image.

### L-5 (Low): profile cache behaviour

**Where:** `internal/nostr/fetcher.go:180-186` caches a failed (nil) lookup for
24 h. A relay can serve an older, validly signed kind 0 (rollback). Once C-2 is
fixed this only affects display name and avatar. **Fix:** cache negative results
briefly (5 min) and bound the cache.

### L-6 (Low): claim semantics

**Where:** `internal/handler/userinfo.go:17-20`.

- `email_verified` uses `omitempty`, so `false` is never sent.
- `profile` (by spec a profile page URL) carries the free-text `about`.

**Fix:** always send `email_verified:false` and drop `profile`.

### L-7 (Low): configuration handling

**Where:** `internal/config/config.go`.

- `config.go:72,92`: `strconv.Atoi` and `time.ParseDuration` errors are discarded,
  so `PORT=abc` silently becomes 8080 and a bad TTL becomes the default.
- `config.go:115-117`: `base_url` defaults to `http://localhost:8080`, which
  becomes the `iss`.
- A trailing slash in `base_url` produces `//authorize` endpoints.
- `/authorize` does not require the `openid` scope.

**Fix:**

- fail on parse errors;
- require `base_url` (absolute URL, no query or fragment, trailing slash trimmed);
- warn on a non-HTTPS non-localhost issuer;
- require `openid` in `scope`.

### L-8 (Low): logging

`middleware.Logger` logs full request URIs, including `state`, `nonce` and
`code_challenge` (not secrets on their own). `userinfo.go:65` logs profile `name`
and `nip05`. No client secrets, codes or tokens are logged. **Fix:** log a
path-only access log and keep identity logging at the npub level.

### L-9 (Low): access tokens

`internal/oauth2/store.go:188-207`: 24 h bearer tokens, no revocation endpoint,
in memory (lost on restart, which is harmless here). Gitea uses the token only
once, to call `/userinfo`. **Fix:** shorten to 10 min, add revocation on code
reuse (M-1), and wipe the token map on shutdown. A revocation endpoint is
optional.

### I-1 (Info): release command

`.claude/commands/release.md` instructs an agent to `git add -A`, commit, tag and
`git push origin main --tags`. It is unrelated to runtime security, but it bypasses
review and can sweep untracked files into a release. Consider removing it or
requiring a human push.

### Not applicable / checked

- **Sessions/cookies:** the original server has no cookies or sessions, so there
  is nothing to steal. CSRF on `/verify` is covered by H-4.
- **Open redirect:** `redirect_uri` is exact-matched before any redirect. Errors
  before validation are rendered as plain text, not redirected.
- **Key management/rotation:** there was no key at all (H-1).
- **Refresh tokens / client credentials grant:** not implemented, which is fine.
- **NIP-42:** not used. NIP-98 kind 27235 is the right primitive for this
  challenge, provided `u`, `method` and the challenge are verified (H-4).

## Remediation status (branch `feat/go-nostr-hardening`)

| ID | Status | Commit | Notes |
|----|--------|--------|-------|
| C-1 | Fixed | `a1c571b` | Port to `nbd-wtf/go-nostr`. `/verify` requires `CheckID()` and `CheckSignature()` (the hash is recomputed from the serialisation). Relay events get the same checks (`555c1eb`). Regression test: `TestVerifyRejections/forged_id_*`, `TestFetchProfileVerifiesEvents`. |
| C-2 | Fixed | `555c1eb` | `preferred_username`/`nickname` = `npub[:25]`, `email` = `<npub>@nostr.invalid`, `email_verified=false` always. Profile data is display-only and sanitised. README forbids `ACCOUNT_LINKING=auto`. |
| H-1 | Fixed | `3f9d328` | RS256 ID tokens, JWKS with RFC 7638 `kid`, full claim set. |
| H-2 | Fixed | `555c1eb` | 100-bit username prefix; full npub in the email. |
| H-3 | Fixed | `555c1eb` | Guarded dialer (non-public IPs refused after DNS), wss-only user relays, max 5 user relays, read/event limits, global dial semaphore, no proxy, no redirects. |
| H-4 | Mitigated | `3f9d328` | `u`, `method`, single `challenge` and the exact sign-in statement are verified. Browser-binding cookie added; CORS removed. **Residual:** NIP-07 extensions remain signing oracles. A user who approves the "Sign in to … via …" prompt on a hostile site can still be phished. This is inherent to NIP-07 and documented in the README. |
| M-1 | Fixed | `3f9d328` | Atomic `ConsumeChallenge`/`ConsumeAuthCode`. Code reuse revokes the issued token. Code TTL is 2 min. |
| M-2 | Fixed | `3f9d328` | PKCE S256 (plain rejected), per-client `require_pkce`, downgrade protection. Gitea itself does not send PKCE. |
| M-3 | Fixed | `3f9d328` | `nonce` stored and echoed. |
| M-4 | Fixed | `c1165ad` | Startup validation rejects an empty, short or placeholder secret. `client_secret_file` supported. |
| M-5 | Fixed | `c1165ad` | Server timeouts, header limit, graceful shutdown. |
| M-6 | Partially fixed | `3f9d328`, `555c1eb` | Store and cache capacity limits, 16 KiB body limit, `state`/`nonce` length limits. **Open:** no built-in per-client rate limiting. Behind the ingress the server sees only the proxy IP, so this belongs at the ingress (documented). |
| M-7 | Mitigated | `555c1eb` | Only `https://` pictures with a DNS hostname on port 443; no IP literals or internal suffixes. **Residual:** a public hostname that resolves to an internal IP can only be stopped by the relying party's egress policy. Gitea v28 has one; `UPDATE_AVATAR=false` is the default and recommended. `nostr.expose_picture: false` drops the claim. |
| M-8 | Fixed | `a1c571b` | `next.orly.dev` and the replace directive removed. `nbd-wtf/go-nostr v0.52.3` is pinned (see dependency note). |
| M-9 | Fixed | `c390aab` | Distroless static nonroot runtime, both images pinned by digest, no baked config. Built and smoke-tested locally with podman. |
| L-1 | Fixed | `3f9d328` | RFC 6749 status codes, `no-store`, single auth method, form-decoded Basic credentials. |
| L-2 | Fixed | `3f9d328` | CSP with nonce, `frame-ancestors 'none'`, `no-referrer`, `no-store`; template parsed once. |
| L-3 | Fixed | `3f9d328`, `c390aab` | `RealIP` removed; chi v5.3.2. |
| L-4 | Fixed | `c390aab` | `toolchain go1.27.2`; the Docker build uses go1.27.2. |
| L-5 | Fixed | `555c1eb` | Negative results cached for 5 min; bounded caches. Rollback to an older valid kind 0 now affects display data only. |
| L-6 | Fixed | `555c1eb` | `email_verified` always present; `profile` and `website` dropped. |
| L-7 | Fixed | `555c1eb`, `c1165ad`, `3f9d328` | Env parse errors fail startup, strict YAML, `base_url` required and normalised, `openid` scope required. |
| L-8 | Fixed | `3f9d328` | Path-only access log; identities logged as truncated npub. |
| L-9 | Partially fixed | `3f9d328` | 10 min access tokens, revocation on code reuse. **Open:** no revocation endpoint, in-memory state (single replica only). Acceptable for Gitea, which uses the token once. |
| I-1 | Open | | Owner decision: `.claude/commands/release.md` still pushes to `main` automatically. |

Remaining relying-party limitations, out of this server's control:

- Gitea's goth `openidConnect` provider does not verify ID token signatures.
  It relies on TLS to the token endpoint, and on `/userinfo`, whose `sub` must
  match.
- It sends neither PKCE nor `nonce`.

Both are supported here for relying parties that do use them.

### Dependency note

`github.com/nbd-wtf/go-nostr` v0.52.3 (2025-11-13) is the latest tag. The
upstream README says the repository is in **maintenance mode** and points to
`fiatjaf.com/nostr` as its successor. That successor is untagged, so you would
have to track `@master`. This project uses only stable primitives from go-nostr:

- `Event`, `CheckID` and `CheckSignature`;
- `Filter.Matches`;
- `ReqEnvelope`;
- `nip19`.

The relay connection itself uses `github.com/coder/websocket` v1.8.15 directly.
A later move to `fiatjaf.com/nostr` should be mechanical.

### Tool results after changes

- `go vet ./...`: clean.
- `staticcheck ./...` (2026.2.1): clean.
- `govulncheck ./...` (go1.27.2): **No vulnerabilities found.**
- `go test ./...` and `go test -race ./...`: pass. The tests cover:
  - challenge verification: forged id, bad signature, tampered content, wrong
    pubkey, wrong kind, too old or future timestamp, wrong `u`/`method`/content,
    unknown, duplicate or missing challenge;
  - replay, expired challenge, missing binding cookie;
  - exact-match `redirect_uri` at `/authorize` and `/token`;
  - code reuse with token revocation, and concurrent single use;
  - PKCE: missing, wrong and correct verifiers, downgrade, `require_pkce`;
  - ID token signature and claims, deterministic userinfo claims despite a
    hostile profile, discovery and JWKS;
  - no CORS, security headers, body limit;
  - SSRF guard, relay URL filtering and capping, event verification from
    relays, config validation.
