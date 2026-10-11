# gitea-nostr-auth

An OAuth2/OpenID Connect provider that lets people sign in to **Gitea** (and
Forgejo) with their Nostr identity. Users sign a login challenge with a
NIP-07 browser extension (Alby, nos2x, ...) or with a NIP-46 remote signer
app such as Amber on Android.

- **NIP-07 login**: the user signs a NIP-98 style kind-27235 event that is
  bound to this server's `/verify` URL, a single-use challenge, and the browser
  that started the flow.
- **NIP-46 login (Amber)**: the login page shows a `nostrconnect://` link
  and QR code. The signer app is asked to sign the same event, which goes
  through the same verification as the extension path.
- **Standard OIDC provider**: discovery, RS256-signed ID tokens, JWKS,
  userinfo, PKCE (S256), `nonce`.
- **Auto-registration in Gitea**: identity claims are derived only from the
  public key, so they are deterministic and cannot collide with existing
  accounts.
- **Profile display data**: name and avatar come from the user's kind-0
  profile, found through their NIP-65 relay list. Relay fetching is guarded
  against SSRF and results are cached.

See [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for the security review of the
upstream code and the status of each finding.

## Identity mapping

| Claim | Value | Source |
|-------|-------|--------|
| `sub` | hex public key | signed login event |
| `preferred_username`, `nickname` | `npub1` + next 20 characters (25 characters, 100 bits), for example `npub1sg6plzptd64u62a878hep` | public key |
| `email` | `<full npub>@nostr.invalid` | public key |
| `email_verified` | always `false` | |
| `name` | kind-0 `display_name` or `name` (sanitised, max 64 characters), else a shortened npub | profile, display only |
| `picture` | kind-0 `picture`, only for `https://` URLs with a DNS host name | profile, display only |

Profile fields such as `name` and `nip05` can be set by anyone to anything.
They are never used as the username or the email. Otherwise an attacker could
publish `{"name":"admin"}` or `{"nip05":"you@your-domain"}` and get linked to
an existing account (see C-2 in the security review). `nostr.invalid` uses a
reserved TLD (RFC 6761) and never receives mail.

## Configure Gitea (current release, v28)

Gitea's "OpenID Connect" authentication source uses goth's `openidConnect`
provider. It reads the following claims:

- `sub` becomes the external user id. The account link is keyed on it.
- `nickname`, then `preferred_username`, becomes the nickname, which is the
  default username source.
- `email`, `name` (full name) and `picture` (avatar) are also read.

Claims from `/userinfo` override those in the ID token. Gitea does not check
`email_verified`.

### 1. Register the client in this server

Generate a secret: `openssl rand -hex 32`. The redirect URI is
`<Gitea ROOT_URL>user/oauth2/<auth source name>/callback`. The source name is
case-sensitive, so use `nostr`.

```yaml
oauth2:
  clients:
    - client_id: "gitea"
      client_secret_file: "/etc/nostr-auth/secret/client_secret"
      redirect_uris:
        - "https://git.circum.space/user/oauth2/nostr/callback"
```

### 2. Add the authentication source

Admin UI path: *Site Administration → Identity & Access → Authentication
Sources → Add*. Use these values:

| Field | Value |
|-------|-------|
| Authentication type | OAuth2 |
| Authentication name | `nostr` (must match the redirect URI) |
| OAuth2 provider | OpenID Connect |
| Client ID (Key) | `gitea` |
| Client Secret | the secret from step 1 |
| OpenID Connect Auto Discovery URL | `https://<auth host>/.well-known/openid-configuration` |
| Additional scopes | `profile email` (`openid` is always added) |
| Skip local 2FA | off |
| Required claim name / Claim name providing group names / admin / restricted group | leave empty (this server issues no group claims) |
| Full name claim name, SSH public key claim name | leave empty |

The same setup from the CLI:

```bash
gitea admin auth add-oauth \
  --name nostr \
  --provider openidConnect \
  --key gitea \
  --secret "$CLIENT_SECRET" \
  --auto-discover-url "https://<auth host>/.well-known/openid-configuration" \
  --scopes "openid profile email"
```

### 3. `app.ini`

```ini
[oauth2_client]
; Create the account on first Nostr login. Without this, Gitea shows a
; "link account / register" page.
ENABLE_AUTO_REGISTRATION = true
; The username comes from the nickname / preferred_username claim, which this
; server sets to the deterministic npub prefix. `preferred_username` also works.
USERNAME = nickname
; NEVER set this to `auto`. With auto, Gitea links a new external login to an
; existing local account that has the same username or primary email.
; `login` (the default) asks for the existing account's password instead;
; `disabled` shows an error.
ACCOUNT_LINKING = login
; Placeholder emails cannot receive mail, so never require confirmation for
; OAuth2 sign-ups.
REGISTER_EMAIL_CONFIRM = false
; Off by default. When on, Gitea fetches the `picture` URL server-side on
; every login. This server passes only https URLs with a DNS host name, but
; make sure Gitea's egress policy blocks internal addresses before enabling it.
UPDATE_AVATAR = false
OPENID_CONNECT_SCOPES = openid profile email

[service]
DISABLE_REGISTRATION = false
; Optional: allow sign-up only through external sources such as Nostr.
ALLOW_ONLY_EXTERNAL_REGISTRATION = true
; If EMAIL_DOMAIN_ALLOWLIST is set, it must contain nostr.invalid.
```

Notes:

- Gitea sends notification mail to the primary address. For Nostr users this
  is `npub…@nostr.invalid`, which fails delivery harmlessly. Users can add and
  verify a real address in their settings.
- Gitea's server makes back-channel calls to the discovery, `/token` and
  `/userinfo` URLs. `base_url` must therefore resolve and be reachable from the
  Gitea pod, not only from browsers. In a tailnet-only setup that means
  tailnet DNS and egress for the Gitea pod, or a `base_url` hostname that also
  resolves inside the cluster to the same service.
- Users can rename themselves in Gitea later. The external login stays bound
  to `sub`, the public key.

### Forgejo

Forgejo uses the same goth `openidConnect` provider and the same
`[oauth2_client]` settings (`ENABLE_AUTO_REGISTRATION`, `USERNAME`,
`ACCOUNT_LINKING`, `UPDATE_AVATAR`). The configuration above applies
unchanged; the auth source is configured the same way in its admin UI or with
`forgejo admin auth add-oauth`. Again, never use `ACCOUNT_LINKING = auto`.

## Configuration

Configure with a YAML file (`-config`, default `config.yaml`) or, if that file
does not exist, with environment variables. Startup fails on unsafe values:

- missing `base_url`;
- the example or a short (< 32 characters) client secret;
- missing redirect URIs;
- out-of-range TTLs.

See [`config.example.yaml`](config.example.yaml) for all options.

| YAML | Environment | Default |
|------|-------------|---------|
| `server.base_url` (required, becomes the OIDC issuer) | `BASE_URL` | |
| `server.host` / `server.port` | `HOST` / `PORT` | `0.0.0.0` / `8080` |
| `oauth2.clients[]` | `OAUTH2_CLIENT_ID`, `OAUTH2_CLIENT_SECRET` or `OAUTH2_CLIENT_SECRET_FILE`, `OAUTH2_REDIRECT_URIS` (comma separated), `OAUTH2_REQUIRE_PKCE` | |
| `oauth2.signing_key_file` | `OAUTH2_SIGNING_KEY_FILE` | ephemeral key |
| `oauth2.code_ttl` / `access_token_ttl` / `id_token_ttl` | `OAUTH2_CODE_TTL` / `OAUTH2_ACCESS_TOKEN_TTL` / `OAUTH2_ID_TOKEN_TTL` | `2m` / `10m` / `5m` |
| `nostr.challenge_ttl` | `NOSTR_CHALLENGE_TTL` | `2m` |
| `nostr.fallback_relays` | `NOSTR_FALLBACK_RELAYS` | see below |
| `nostr.max_user_relays` | `NOSTR_MAX_USER_RELAYS` | `5` |
| `nostr.email_domain` | `NOSTR_EMAIL_DOMAIN` | `nostr.invalid` |
| `nostr.expose_picture` | `NOSTR_EXPOSE_PICTURE` | `true` |
| `nostr.allow_private_relays` (testing only) | `NOSTR_ALLOW_PRIVATE_RELAYS` | `false` |
| `nostr.nip46.relay` (empty: NIP-46 login off) | `NOSTR_NIP46_RELAY` | |
| `nostr.nip46.timeout` | `NOSTR_NIP46_TIMEOUT` | `2m` |
| `nostr.nip46.allow_private_relay` | `NOSTR_NIP46_ALLOW_PRIVATE_RELAY` | `false` |

**Signing key.** Without `signing_key_file`, a fresh RSA key is generated on
every start. That is fine for Gitea, which consumes ID tokens immediately.
Mount a persistent key if other relying parties cache the JWKS:
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing.pem`.
To rotate, replace the file and restart. Tokens are short-lived, so no overlap
period is needed for Gitea.

**NIP-46 relay.** Every remote signer login uses this one relay. It must:

- be reachable from this server and from the users' phones, so for phones
  outside the tailnet it must be public;
- accept kind-24133 events from any public key, because each login uses a
  fresh client key (a relay with a web-of-trust or allowlist write policy
  rejects them);
- not require NIP-42 authentication.

The connection goes through the same address guard as profile lookups.
`allow_private_relay` lifts the guard for this relay only, for example for a
relay inside the cluster. A Kubernetes network policy must also allow egress
to it.

**State.** Challenges, codes, tokens and NIP-46 sessions live in memory. Run a single replica,
or use sticky sessions.

## Build and run

```bash
go build ./cmd/nostr-oauth2-server
./nostr-oauth2-server -config config.yaml
```

Container image: a static binary on `distroless/static-debian13:nonroot`,
pinned by digest. It runs as UID 65532, needs no writable filesystem, and has
no config baked in.

```bash
docker build -t gitea-nostr-auth .
docker run --read-only -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/nostr-auth/config.yaml:ro \
  gitea-nostr-auth
```

Kubernetes hints:

- probe `GET /healthz`;
- mount the config and secrets read-only;
- `readOnlyRootFilesystem: true`, `runAsNonRoot: true`,
  `allowPrivilegeEscalation: false`, and drop all capabilities;
- rate-limit `/authorize` and `/verify` at the ingress. Behind a proxy the
  server only sees the proxy's IP, so it does not rate-limit per client.

## How it works

1. Gitea redirects to `/authorize`. This server validates the client and the
   exact `redirect_uri`, plus `scope=openid`, PKCE and `nonce`. It sets an
   HttpOnly `SameSite=Strict` binding cookie and renders the login page with a
   256-bit single-use challenge.
2. The page asks the NIP-07 extension to sign a kind-27235 event with these
   tags: `["u", "<base_url>/verify"]`, `["method", "POST"]`,
   `["challenge", <nonce>]`. The content is `Sign in to <gitea host> via <auth host>`.
3. `/verify` checks the following:
   - the kind;
   - the timestamp, within the challenge TTL;
   - that the event id is the hash of the canonical serialisation, and the
     Schnorr signature over that hash;
   - the `u`, `method` and content values;
   - the binding cookie.

   It then consumes the challenge atomically and returns a redirect to Gitea
   with a 2-minute single-use code.

   With a NIP-46 signer instead, the page calls `/nip46/start`. The server
   checks that the challenge was issued to this browser, creates a client
   keypair and a 128-bit one-time secret, subscribes on the configured relay
   and returns `nostrconnect://<client pubkey>?relay=…&secret=…&perms=sign_event:27235`
   as a link and QR code. The first signer that answers with the secret
   becomes the session's signer. The server sends it one `sign_event` request
   for the login event (NIP-44 encrypted) and accepts the answer only from
   that signer. The page long-polls `/nip46/wait`, which requires the binding
   cookie. When the signed event arrives, `/nip46/wait` runs the same checks
   as `/verify` (step 3). A session ends after `nip46.timeout` or when the
   challenge expires, whichever comes first.
4. Gitea redeems the code at `/token`, authenticating with
   `client_secret_basic` or `client_secret_post`. It receives an RS256 ID
   token and a 10-minute access token, then calls `/userinfo`.
5. For `/userinfo`, the server fetches the user's NIP-65 relay list from the
   fallback relays. It then queries up to `max_user_relays` of the user's
   `wss://` read relays plus the fallback relays for kind 0. Every event's id,
   signature and author are verified. Connections to non-public addresses
   (private, loopback, link-local and metadata, CGNAT/tailnet) are refused
   after DNS resolution. Results are cached for 24 h, and failed lookups for
   5 minutes.

Default fallback relays: `wss://relay.nostr.band/`, `wss://nostr.wine/`,
`wss://nos.lol/`, `wss://relay.primal.net/`, `wss://purplepag.es/`.

Residual risk: NIP-07 extensions and NIP-46 signers sign whatever a page asks for. A user who
approves a kind-27235 "Sign in to … via …" signature on a hostile site lets
that site log in as them. The statement names both hosts so the prompt makes
this visible. Only approve it on the auth server's own page. Anyone who sees
a NIP-46 QR code can answer it first. They can then make that browser sign
in as their own Nostr identity, but not as yours.

## API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET /.well-known/jwks.json` | public signing key |
| `GET /authorize` | authorization endpoint (login page) |
| `POST /verify` | verifies the signed Nostr event (called by the login page) |
| `POST /nip46/start` | starts a remote signer login (only with `nostr.nip46.relay`) |
| `POST /nip46/wait` | long-polls a remote signer login and completes it |
| `POST /token` | code exchange |
| `GET/POST /userinfo` | user claims |
| `GET /healthz` | liveness |

## License

Public domain ([Unlicense](LICENSE)). Originally written by mleku; see
[NOTICE](NOTICE).
