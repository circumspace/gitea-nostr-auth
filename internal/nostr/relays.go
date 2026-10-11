package nostr

import (
	"net"
	"net/url"
	"strings"
)

// Nip65Relay represents a relay from a user's NIP-65 relay list
type Nip65Relay struct {
	URL   string `json:"url"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}

// ProfileMetadata represents parsed kind 0 profile data. All fields are
// attacker controlled; they are sanitised when parsed and only used for
// display purposes.
type ProfileMetadata struct {
	Pubkey      string `json:"pubkey"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Nip05       string `json:"nip05,omitempty"`
}

// GetDisplayName returns the best display name, or "" if none is set.
func (p *ProfileMetadata) GetDisplayName() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.Name
}

const maxRelayURLLength = 256

// normalizeRelayURL validates a relay URL. allowWS permits plain ws:// (only
// for operator-configured relays or tests). It returns "" if the URL is not
// acceptable.
func normalizeRelayURL(raw string, allowWS bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxRelayURLLength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "wss":
	case "ws":
		if !allowWS {
			return ""
		}
	default:
		return ""
	}
	if !allowWS {
		// User-supplied relays: reject IP literals and obviously internal
		// names outright; the dialer guard catches the rest after DNS.
		h := strings.ToLower(u.Hostname())
		if net.ParseIP(h) != nil || h == "localhost" || strings.HasSuffix(h, ".localhost") ||
			strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") ||
			strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".cluster.local") || !strings.Contains(h, ".") {
			return ""
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}
