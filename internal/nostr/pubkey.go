package nostr

import (
	"next.orly.dev/pkg/nostr/encoders/bech32encoding"
	"next.orly.dev/pkg/nostr/encoders/hex"
)

// PubkeyToNpub converts a hex public key to bech32 npub format
func PubkeyToNpub(hexPubkey string) string {
	npub, err := bech32encoding.HexToNpub([]byte(hexPubkey))
	if err != nil {
		// If encoding fails, return truncated hex
		if len(hexPubkey) > 16 {
			return hexPubkey[:16] + "..."
		}
		return hexPubkey
	}
	return string(npub)
}

// NpubToPubkey converts a bech32 npub to hex public key
func NpubToPubkey(npub string) (string, error) {
	pkBytes, err := bech32encoding.NpubToBytes([]byte(npub))
	if err != nil {
		return "", err
	}
	return hex.Enc(pkBytes), nil
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
