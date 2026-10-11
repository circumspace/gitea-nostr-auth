package nostr

import (
	"fmt"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// PubkeyToNpub converts a hex public key to bech32 npub format
func PubkeyToNpub(hexPubkey string) string {
	npub, err := nip19.EncodePublicKey(hexPubkey)
	if err != nil {
		// If encoding fails, return truncated hex
		if len(hexPubkey) > 16 {
			return hexPubkey[:16] + "..."
		}
		return hexPubkey
	}
	return npub
}

// NpubToPubkey converts a bech32 npub to hex public key
func NpubToPubkey(npub string) (string, error) {
	prefix, value, err := nip19.Decode(npub)
	if err != nil {
		return "", err
	}
	pk, ok := value.(string)
	if prefix != "npub" || !ok {
		return "", fmt.Errorf("not an npub: %q", prefix)
	}
	return pk, nil
}

// TruncateNpub returns a shortened npub for display
func TruncateNpub(npub string) string {
	if len(npub) <= 20 {
		return npub
	}
	return npub[:12] + "..." + npub[len(npub)-8:]
}

// GenerateUsername creates a username from a pubkey
// Prefers NIP-05 identifier if available, otherwise uses npub prefix
func GenerateUsername(hexPubkey string) string {
	npub := PubkeyToNpub(hexPubkey)
	// Use first 12 chars of npub (npub1 + 7 chars)
	if len(npub) > 12 {
		return npub[:12]
	}
	return npub
}

// GeneratePlaceholderEmail creates a placeholder email for Gitea
func GeneratePlaceholderEmail(hexPubkey string) string {
	username := GenerateUsername(hexPubkey)
	return username + "@nostr.local"
}
