# gitea-nostr-auth

An OAuth2/OIDC provider that enables Nostr NIP-07 browser extension authentication for Gitea. Allows users to sign in to Gitea using their Nostr identity.

## Features

- **NIP-07 Authentication**: Uses browser extensions (Alby, nos2x, etc.) for signing
- **OAuth2/OIDC Compatible**: Works as a standard OpenID Connect provider for Gitea
- **Auto-Registration**: Automatically creates Gitea accounts for new Nostr users
- **Profile Fetching**: Fetches user profiles (name, picture, NIP-05) from Nostr relays
- **Smart Relay Discovery**: First fetches user's NIP-65 relay list, then queries those relays for profile
- **Caching**: 24-hour cache for relay lists and profiles to minimize relay queries

## Quick Start

### 1. Build

```bash
go build ./cmd/nostr-oauth2-server
```

### 2. Configure

Copy `config.example.yaml` to `config.yaml` and update:

```yaml
server:
  port: 8080
  base_url: "https://nostr-auth.example.com"

oauth2:
  clients:
    - client_id: "gitea"
      client_secret: "your-secure-secret"  # Generate with: openssl rand -hex 32
      redirect_uris:
        - "https://gitea.example.com/user/oauth2/nostr/callback"
```

### 3. Run

```bash
./nostr-oauth2-server -config config.yaml
```

Or with environment variables:

```bash
PORT=8080 \
BASE_URL=https://nostr-auth.example.com \
OAUTH2_CLIENT_ID=gitea \
OAUTH2_CLIENT_SECRET=your-secure-secret \
OAUTH2_REDIRECT_URIS=https://gitea.example.com/user/oauth2/nostr/callback \
./nostr-oauth2-server
```

### 4. Configure Gitea

Add the OAuth2 authentication source:

```bash
gitea admin auth add-oauth \
  --name "Nostr" \
  --provider openidConnect \
  --key "gitea" \
  --secret "your-secure-secret" \
  --auto-discover-url "https://nostr-auth.example.com/.well-known/openid-configuration"
```

Enable auto-registration in Gitea's `app.ini`:

```ini
[service]
DISABLE_REGISTRATION = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = true
```

## Docker

```bash
docker build -t nostr-oauth2-server .
docker run -p 8080:8080 -v $(pwd)/config.yaml:/app/config.yaml nostr-oauth2-server
```

## How It Works

### Authentication Flow

1. User clicks "Login with Nostr" on Gitea
2. Gitea redirects to nostr-oauth2-server's `/authorize` endpoint
3. Login page uses `window.nostr` (NIP-07) to get pubkey and sign a challenge
4. Server verifies signature and issues an OAuth2 authorization code
5. Gitea exchanges code for access token and fetches user info
6. User is logged in (or account is created if new)

### Profile Fetching

When Gitea requests user info, the server:

1. **Fetches NIP-65 relay list (kind 10002)** from fallback relays to find user's preferred relays
2. **Queries user's read relays + fallbacks** for their profile (kind 0)
3. **Extracts profile data**: name, display_name, picture, NIP-05, website, etc.
4. **Caches results** for 24 hours to minimize relay queries

This ensures profiles are found even if only stored on the user's preferred relays.

### Fallback Relays

Default relays used for initial queries (configurable):
- `wss://relay.nostr.band/`
- `wss://nostr.wine/`
- `wss://nos.lol/`
- `wss://relay.primal.net/`
- `wss://purplepag.es/`

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery document |
| `/authorize` | OAuth2 authorization (shows login page) |
| `/verify` | Verify signed Nostr event |
| `/token` | Exchange auth code for access token |
| `/userinfo` | Get user profile (npub, username, email) |

## Security

- Challenges are single-use and expire after 60 seconds
- Event signatures are verified using secp256k1
- Timestamps must be within a 60-second window
- HTTPS required in production

## License

This is free and unencumbered software released into the public domain (Unlicense).
