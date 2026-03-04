package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	OAuth2  OAuth2Config  `yaml:"oauth2"`
	Nostr   NostrConfig   `yaml:"nostr"`
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

type OAuth2Config struct {
	Clients []ClientConfig `yaml:"clients"`
}

type ClientConfig struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

type NostrConfig struct {
	ChallengeTTL   time.Duration `yaml:"challenge_ttl"`
	FallbackRelays []string      `yaml:"fallback_relays"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg.setDefaults()
	return &cfg, nil
}

func FromEnv() *Config {
	cfg := &Config{}

	// Server config
	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port, _ = strconv.Atoi(port)
	}
	cfg.Server.Host = os.Getenv("HOST")
	cfg.Server.BaseURL = os.Getenv("BASE_URL")

	// OAuth2 client config (single client from env)
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	redirectURIs := os.Getenv("OAUTH2_REDIRECT_URIS")

	if clientID != "" {
		cfg.OAuth2.Clients = []ClientConfig{{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURIs: strings.Split(redirectURIs, ","),
		}}
	}

	// Nostr config
	if ttl := os.Getenv("NOSTR_CHALLENGE_TTL"); ttl != "" {
		cfg.Nostr.ChallengeTTL, _ = time.ParseDuration(ttl)
	}
	if relays := os.Getenv("NOSTR_FALLBACK_RELAYS"); relays != "" {
		cfg.Nostr.FallbackRelays = strings.Split(relays, ",")
	}

	cfg.setDefaults()
	return cfg
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
	if c.Server.BaseURL == "" {
		c.Server.BaseURL = fmt.Sprintf("http://localhost:%d", c.Server.Port)
	}
	if c.Nostr.ChallengeTTL == 0 {
		c.Nostr.ChallengeTTL = 60 * time.Second
	}
	if len(c.Nostr.FallbackRelays) == 0 {
		c.Nostr.FallbackRelays = DefaultFallbackRelays
	}
}

func (c *Config) GetClient(clientID string) *ClientConfig {
	for i := range c.OAuth2.Clients {
		if c.OAuth2.Clients[i].ClientID == clientID {
			return &c.OAuth2.Clients[i]
		}
	}
	return nil
}

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
