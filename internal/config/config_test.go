package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSecret = "0123456789abcdef0123456789abcdef"

func validConfig() *Config {
	c := &Config{}
	c.Server.BaseURL = "https://auth.example.com/"
	c.OAuth2.Clients = []ClientConfig{{
		ClientID:     "gitea",
		ClientSecret: goodSecret,
		RedirectURIs: []string{"https://git.example.com/user/oauth2/nostr/callback"},
	}}
	c.setDefaults()
	return c
}

func TestValidateAcceptsGoodConfig(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Server.BaseURL != "https://auth.example.com" {
		t.Fatalf("trailing slash not trimmed: %q", c.Server.BaseURL)
	}
}

func TestValidateRejectsUnsafeConfig(t *testing.T) {
	cases := map[string]func(c *Config){
		"placeholder secret": func(c *Config) { c.OAuth2.Clients[0].ClientSecret = PlaceholderSecret },
		"empty secret":       func(c *Config) { c.OAuth2.Clients[0].ClientSecret = "" },
		"short secret":       func(c *Config) { c.OAuth2.Clients[0].ClientSecret = "short" },
		"no base url":        func(c *Config) { c.Server.BaseURL = "" },
		"relative base url":  func(c *Config) { c.Server.BaseURL = "auth.example.com" },
		"base url query":     func(c *Config) { c.Server.BaseURL = "https://a.example.com?x=1" },
		"no clients":         func(c *Config) { c.OAuth2.Clients = nil },
		"no redirect uris":   func(c *Config) { c.OAuth2.Clients[0].RedirectURIs = nil },
		"redirect fragment":  func(c *Config) { c.OAuth2.Clients[0].RedirectURIs = []string{"https://g.example.com/cb#x"} },
		"redirect relative":  func(c *Config) { c.OAuth2.Clients[0].RedirectURIs = []string{"/cb"} },
		"duplicate client":   func(c *Config) { c.OAuth2.Clients = append(c.OAuth2.Clients, c.OAuth2.Clients[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateRedirectURIExactMatch(t *testing.T) {
	c := validConfig()
	ok := "https://git.example.com/user/oauth2/nostr/callback"
	if !c.ValidateRedirectURI("gitea", ok) {
		t.Fatal("registered redirect_uri rejected")
	}
	for _, bad := range []string{
		ok + "/",
		ok + "?x=1",
		ok + "/../../evil",
		"https://GIT.example.com/user/oauth2/nostr/callback",
		"http://git.example.com/user/oauth2/nostr/callback",
		"https://git.example.com/user/oauth2/nostr/callbackx",
		"https://git.example.com.evil.com/user/oauth2/nostr/callback",
		"https://git.example.com/user/oauth2/nostr",
		"",
	} {
		if c.ValidateRedirectURI("gitea", bad) {
			t.Errorf("redirect_uri %q accepted", bad)
		}
	}
	if c.ValidateRedirectURI("other", ok) {
		t.Error("redirect_uri accepted for unknown client")
	}
}

func TestFromEnvRejectsParseErrors(t *testing.T) {
	t.Setenv("PORT", "abc")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for invalid PORT")
	}
	t.Setenv("PORT", "8080")
	t.Setenv("NOSTR_CHALLENGE_TTL", "soon")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error for invalid NOSTR_CHALLENGE_TTL")
	}
}

func TestClientSecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte(goodSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := `server:
  base_url: "https://auth.example.com"
oauth2:
  clients:
    - client_id: gitea
      client_secret_file: "` + p + `"
      redirect_uris: ["https://git.example.com/cb"]
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.OAuth2.Clients[0].ClientSecret != goodSecret {
		t.Fatalf("secret not loaded from file: %q", c.OAuth2.Clients[0].ClientSecret)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("server:\n  base_ur1: x\n"), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "base_ur1") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestExampleConfigParsesAndRejectsPlaceholder(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("example config does not parse: %v", err)
	}
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "example client_secret") {
		t.Fatalf("expected placeholder secret rejection only, got %v", err)
	}
	c.OAuth2.Clients[0].ClientSecret = goodSecret
	if err := c.Validate(); err != nil {
		t.Fatalf("example config with real secret invalid: %v", err)
	}
}
