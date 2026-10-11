package nostr

import (
	"fmt"
	"regexp"

	"github.com/nbd-wtf/go-nostr/nip19"
)

var hexPubkeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// IsHexPubkey reports whether s is a 32-byte lowercase hex public key.
func IsHexPubkey(s string) bool { return hexPubkeyRE.MatchString(s) }

// PubkeyToNpub converts a hex public key to bech32 npub format.
// It returns an empty string for invalid input.
func PubkeyToNpub(hexPubkey string) string {
	if !IsHexPubkey(hexPubkey) {
		return ""
	}
	npub, err := nip19.EncodePublicKey(hexPubkey)
	if err != nil {
		return ""
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
