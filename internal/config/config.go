package config

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
)

// PlaceholderSecret is the client secret shipped in config.example.yaml.
// Startup is refused while it is still in use.
const PlaceholderSecret = "change-me-to-a-secure-secret"

// MinClientSecretLength is the minimum accepted client secret length.
const MinClientSecretLength = 32

type Config struct {
	Server ServerConfig `yaml:"server"`
	OAuth2 OAuth2Config `yaml:"oauth2"`
	Nostr  NostrConfig  `yaml:"nostr"`
}

type ServerConfig struct {
	Port    int    `yaml:"port"`
	Host    string `yaml:"host"`
	BaseURL string `yaml:"base_url"`
}

func (s ServerConfig) Address() string {
	host := s.Host
	if host == "" {
		host = "0.0.0.0"
	}
	port := s.Port
	if port == 0 {
		port = 8080
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// IsHTTPS reports whether the public base URL uses https.
func (s ServerConfig) IsHTTPS() bool {
	return strings.HasPrefix(strings.ToLower(s.BaseURL), "https://")
}

type OAuth2Config struct {
	Clients []ClientConfig `yaml:"clients"`
	// SigningKeyFile is a PEM file with an RSA private key (PKCS#1 or PKCS#8,
	// >= 2048 bits) used to sign ID tokens. If empty, an ephemeral key is
	// generated at startup.
	SigningKeyFile string        `yaml:"signing_key_file"`
	CodeTTL        time.Duration `yaml:"code_ttl"`
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`
	IDTokenTTL     time.Duration `yaml:"id_token_ttl"`
}

type ClientConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// ClientSecretFile, if set, is read and overrides ClientSecret
	// (e.g. a mounted Kubernetes secret).
	ClientSecretFile string   `yaml:"client_secret_file"`
	RedirectURIs     []string `yaml:"redirect_uris"`
	// RequirePKCE rejects authorization requests without an S256
	// code_challenge for this client.
	RequirePKCE bool `yaml:"require_pkce"`
}

type NostrConfig struct {
	ChallengeTTL   time.Duration `yaml:"challenge_ttl"`
	FallbackRelays []string      `yaml:"fallback_relays"`
	// MaxUserRelays caps how many relays from a user's NIP-65 list are queried.
	MaxUserRelays int `yaml:"max_user_relays"`
	// AllowPrivateRelays disables the SSRF guard that blocks connections to
	// loopback, private, link-local and CGNAT/tailnet addresses. Only for
	// testing or for a deliberately internal relay.
	AllowPrivateRelays bool `yaml:"allow_private_relays"`
	// EmailDomain is the domain of the placeholder email addresses handed to
	// the relying party. It must never receive mail; the default is the
	// reserved TLD "nostr.invalid" (RFC 6761).
	EmailDomain string `yaml:"email_domain"`
	// ExposePicture controls whether the (sanitised, https-only) kind-0
	// picture URL is returned as the "picture" claim.
	ExposePicture *bool `yaml:"expose_picture"`
	// NIP46 enables login with a remote signer such as Amber.
	NIP46 NIP46Config `yaml:"nip46"`
}

// NIP46Config configures login through a NIP-46 remote signer. It is off
// while Relay is empty.
type NIP46Config struct {
	// Relay carries all messages between this server and signers. Both this
	// server and the user's signer app must reach it.
	Relay string `yaml:"relay"`
	// Timeout bounds one remote signer login. The login challenge's own
	// expiry also applies.
	Timeout time.Duration `yaml:"timeout"`
	// AllowPrivateRelay lets Relay resolve to a private, loopback or
	// tailnet address.
	AllowPrivateRelay bool `yaml:"allow_private_relay"`
}

func (n NIP46Config) Enabled() bool { return n.Relay != "" }

// PictureEnabled reports whether the picture claim is emitted (default true).
func (n NostrConfig) PictureEnabled() bool {
	return n.ExposePicture == nil || *n.ExposePicture
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg.setDefaults()
	if err := cfg.resolveSecrets(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// FromEnv builds a configuration from environment variables.
func FromEnv() (*Config, error) {
	cfg := &Config{}
	var errs []error

	if port := os.Getenv("PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			errs = append(errs, fmt.Errorf("PORT: %w", err))
		}
		cfg.Server.Port = p
	}
	cfg.Server.Host = os.Getenv("HOST")
	cfg.Server.BaseURL = os.Getenv("BASE_URL")

	// OAuth2 client config (single client from env)
	if clientID := os.Getenv("OAUTH2_CLIENT_ID"); clientID != "" {
		client := ClientConfig{
			ClientID:         clientID,
			ClientSecret:     os.Getenv("OAUTH2_CLIENT_SECRET"),
			ClientSecretFile: os.Getenv("OAUTH2_CLIENT_SECRET_FILE"),
		}
		for _, u := range strings.Split(os.Getenv("OAUTH2_REDIRECT_URIS"), ",") {
			if u = strings.TrimSpace(u); u != "" {
				client.RedirectURIs = append(client.RedirectURIs, u)
			}
		}
		if v := os.Getenv("OAUTH2_REQUIRE_PKCE"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("OAUTH2_REQUIRE_PKCE: %w", err))
			}
			client.RequirePKCE = b
		}
		cfg.OAuth2.Clients = []ClientConfig{client}
	}
	cfg.OAuth2.SigningKeyFile = os.Getenv("OAUTH2_SIGNING_KEY_FILE")

	parseDur := func(name string, dst *time.Duration) {
		if v := os.Getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			}
			*dst = d
		}
	}
	parseDur("OAUTH2_CODE_TTL", &cfg.OAuth2.CodeTTL)
	parseDur("OAUTH2_ACCESS_TOKEN_TTL", &cfg.OAuth2.AccessTokenTTL)
	parseDur("OAUTH2_ID_TOKEN_TTL", &cfg.OAuth2.IDTokenTTL)
	parseDur("NOSTR_CHALLENGE_TTL", &cfg.Nostr.ChallengeTTL)

	if relays := os.Getenv("NOSTR_FALLBACK_RELAYS"); relays != "" {
		for _, r := range strings.Split(relays, ",") {
			if r = strings.TrimSpace(r); r != "" {
				cfg.Nostr.FallbackRelays = append(cfg.Nostr.FallbackRelays, r)
			}
		}
	}
	if v := os.Getenv("NOSTR_MAX_USER_RELAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("NOSTR_MAX_USER_RELAYS: %w", err))
		}
		cfg.Nostr.MaxUserRelays = n
	}
	if v := os.Getenv("NOSTR_ALLOW_PRIVATE_RELAYS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("NOSTR_ALLOW_PRIVATE_RELAYS: %w", err))
		}
		cfg.Nostr.AllowPrivateRelays = b
	}
	if v := os.Getenv("NOSTR_EXPOSE_PICTURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("NOSTR_EXPOSE_PICTURE: %w", err))
		}
		cfg.Nostr.ExposePicture = &b
	}
	cfg.Nostr.EmailDomain = os.Getenv("NOSTR_EMAIL_DOMAIN")
	cfg.Nostr.NIP46.Relay = os.Getenv("NOSTR_NIP46_RELAY")
	parseDur("NOSTR_NIP46_TIMEOUT", &cfg.Nostr.NIP46.Timeout)
	if v := os.Getenv("NOSTR_NIP46_ALLOW_PRIVATE_RELAY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("NOSTR_NIP46_ALLOW_PRIVATE_RELAY: %w", err))
		}
		cfg.Nostr.NIP46.AllowPrivateRelay = b
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	cfg.setDefaults()
	if err := cfg.resolveSecrets(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// DefaultFallbackRelays are well-known relays that aggregate profile data
var DefaultFallbackRelays = []string{
	"wss://relay.nostr.band/",
	"wss://nostr.wine/",
	"wss://nos.lol/",
	"wss://relay.primal.net/",
	"wss://purplepag.es/",
}

func (c *Config) setDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	c.Server.BaseURL = strings.TrimRight(c.Server.BaseURL, "/")
	if c.OAuth2.CodeTTL == 0 {
		c.OAuth2.CodeTTL = 2 * time.Minute
	}
	if c.OAuth2.AccessTokenTTL == 0 {
		c.OAuth2.AccessTokenTTL = 10 * time.Minute
	}
	if c.OAuth2.IDTokenTTL == 0 {
		c.OAuth2.IDTokenTTL = 5 * time.Minute
	}
	if c.Nostr.ChallengeTTL == 0 {
		c.Nostr.ChallengeTTL = 2 * time.Minute
	}
	if len(c.Nostr.FallbackRelays) == 0 {
		c.Nostr.FallbackRelays = DefaultFallbackRelays
	}
	if c.Nostr.MaxUserRelays == 0 {
		c.Nostr.MaxUserRelays = 5
	}
	if c.Nostr.EmailDomain == "" {
		c.Nostr.EmailDomain = "nostr.invalid"
	}
	if c.Nostr.NIP46.Timeout == 0 {
		c.Nostr.NIP46.Timeout = 2 * time.Minute
	}
}

func (c *Config) resolveSecrets() error {
	for i := range c.OAuth2.Clients {
		cl := &c.OAuth2.Clients[i]
		if cl.ClientSecretFile == "" {
			continue
		}
		b, err := os.ReadFile(cl.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("client %q: reading client_secret_file: %w", cl.ClientID, err)
		}
		cl.ClientSecret = strings.TrimSpace(string(b))
	}
	return nil
}

// Validate checks the configuration for unsafe or inconsistent values.
func (c *Config) Validate() error {
	var errs []error

	if c.Server.BaseURL == "" {
		errs = append(errs, errors.New("server.base_url (BASE_URL) is required; it becomes the OIDC issuer"))
	} else if u, err := url.Parse(c.Server.BaseURL); err != nil || !u.IsAbs() || u.Host == "" ||
		(u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		errs = append(errs, fmt.Errorf("server.base_url %q must be an absolute http(s) URL without query, fragment or userinfo", c.Server.BaseURL))
	} else if u.Scheme != "https" && !isLocalHost(u.Hostname()) {
		log.Printf("WARNING: server.base_url %q is not https; use https for anything but local testing", c.Server.BaseURL)
	}

	if len(c.OAuth2.Clients) == 0 {
		errs = append(errs, errors.New("at least one oauth2 client must be configured"))
	}
	seen := map[string]bool{}
	for _, cl := range c.OAuth2.Clients {
		switch {
		case cl.ClientID == "":
			errs = append(errs, errors.New("oauth2 client with empty client_id"))
			continue
		case seen[cl.ClientID]:
			errs = append(errs, fmt.Errorf("duplicate client_id %q", cl.ClientID))
		}
		seen[cl.ClientID] = true
		if cl.ClientSecret == PlaceholderSecret {
			errs = append(errs, fmt.Errorf("client %q still uses the example client_secret", cl.ClientID))
		} else if len(cl.ClientSecret) < MinClientSecretLength {
			errs = append(errs, fmt.Errorf("client %q: client_secret must be at least %d characters (openssl rand -hex 32)", cl.ClientID, MinClientSecretLength))
		}
		if len(cl.RedirectURIs) == 0 {
			errs = append(errs, fmt.Errorf("client %q: at least one redirect_uri is required", cl.ClientID))
		}
		for _, ru := range cl.RedirectURIs {
			u, err := url.Parse(ru)
			if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
				errs = append(errs, fmt.Errorf("client %q: redirect_uri %q must be an absolute http(s) URL without fragment", cl.ClientID, ru))
			}
		}
	}

	if c.Nostr.ChallengeTTL < 10*time.Second || c.Nostr.ChallengeTTL > 10*time.Minute {
		errs = append(errs, fmt.Errorf("nostr.challenge_ttl %s must be between 10s and 10m", c.Nostr.ChallengeTTL))
	}
	if c.OAuth2.CodeTTL > 10*time.Minute {
		errs = append(errs, fmt.Errorf("oauth2.code_ttl %s must not exceed 10m", c.OAuth2.CodeTTL))
	}
	if c.OAuth2.AccessTokenTTL > 24*time.Hour {
		errs = append(errs, fmt.Errorf("oauth2.access_token_ttl %s must not exceed 24h", c.OAuth2.AccessTokenTTL))
	}
	if c.OAuth2.IDTokenTTL > time.Hour {
		errs = append(errs, fmt.Errorf("oauth2.id_token_ttl %s must not exceed 1h", c.OAuth2.IDTokenTTL))
	}
	if c.Nostr.MaxUserRelays < 0 || c.Nostr.MaxUserRelays > 20 {
		errs = append(errs, fmt.Errorf("nostr.max_user_relays %d must be between 0 and 20", c.Nostr.MaxUserRelays))
	}
	if strings.ContainsAny(c.Nostr.EmailDomain, "@ /") {
		errs = append(errs, fmt.Errorf("nostr.email_domain %q is invalid", c.Nostr.EmailDomain))
	}
	if r := c.Nostr.NIP46.Relay; r != "" && nostr.NormalizeOperatorRelayURL(r) == "" {
		errs = append(errs, fmt.Errorf("nostr.nip46.relay %q must be a ws:// or wss:// URL", r))
	}
	if t := c.Nostr.NIP46.Timeout; t < 30*time.Second || t > 10*time.Minute {
		errs = append(errs, fmt.Errorf("nostr.nip46.timeout %s must be between 30s and 10m", t))
	}
	return errors.Join(errs...)
}

func isLocalHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".localhost")
}

func (c *Config) GetClient(clientID string) *ClientConfig {
	for i := range c.OAuth2.Clients {
		if c.OAuth2.Clients[i].ClientID == clientID {
			return &c.OAuth2.Clients[i]
		}
	}
	return nil
}

// ValidateRedirectURI reports whether redirectURI is registered for the
// client. Matching is exact string comparison (no prefix, case or
// normalisation tricks), as required by the OAuth 2.0 Security BCP.
func (c *Config) ValidateRedirectURI(clientID, redirectURI string) bool {
	client := c.GetClient(clientID)
	if client == nil {
		return false
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}
