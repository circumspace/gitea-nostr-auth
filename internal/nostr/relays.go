package nostr

// Nip65Relay represents a relay from a user's NIP-65 relay list
type Nip65Relay struct {
	URL   string `json:"url"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}

// ProfileMetadata represents parsed kind 0 profile data
type ProfileMetadata struct {
	Pubkey      string `json:"pubkey"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Banner      string `json:"banner,omitempty"`
	About       string `json:"about,omitempty"`
	Website     string `json:"website,omitempty"`
	Nip05       string `json:"nip05,omitempty"`
	Lud06       string `json:"lud06,omitempty"`
	Lud16       string `json:"lud16,omitempty"`
}

// GetUsername returns the best username from profile metadata
func (p *ProfileMetadata) GetUsername() string {
	// Prefer NIP-05 identifier (without domain for uniqueness)
	if p.Nip05 != "" {
		return p.Nip05
	}
	// Then name
	if p.Name != "" {
		return p.Name
	}
	// Then display_name
	if p.DisplayName != "" {
		return p.DisplayName
	}
	// Fallback to truncated npub
	return GenerateUsername(p.Pubkey)
}

// GetDisplayName returns the best display name
func (p *ProfileMetadata) GetDisplayName() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	if p.Name != "" {
		return p.Name
	}
	return TruncateNpub(PubkeyToNpub(p.Pubkey))
}
