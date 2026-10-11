package nostr

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// UsernameLength is the length of the deterministic username: "npub1" plus 20
// bech32 characters, i.e. 100 bits of the public key. That is far beyond what
// key grinding can reach, and fits Gitea's 40 character username limit.
const UsernameLength = 25

// Username returns the deterministic username for a public key. It is the
// only value handed to the relying party as preferred_username/nickname.
// Profile data (name, nip05) is attacker controlled and never used here.
func Username(hexPubkey string) (string, error) {
	npub := PubkeyToNpub(hexPubkey)
	if npub == "" {
		return "", fmt.Errorf("invalid public key")
	}
	return npub[:UsernameLength], nil
}

// PlaceholderEmail returns a deterministic, non-routable email address for a
// public key: the full npub (63 characters, within the 64 character local-part
// limit) at the given domain, by default the reserved TLD "nostr.invalid".
func PlaceholderEmail(hexPubkey, domain string) (string, error) {
	npub := PubkeyToNpub(hexPubkey)
	if npub == "" {
		return "", fmt.Errorf("invalid public key")
	}
	return npub + "@" + domain, nil
}

const maxDisplayNameRunes = 64

// SanitizeDisplayName strips control and format characters (including bidi
// overrides and zero-width characters), collapses whitespace and limits the
// length. The result is display-only and must not be used for identity.
func SanitizeDisplayName(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || r == utf8.RuneError {
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
			n++
		}
		space = false
		if n >= maxDisplayNameRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

const maxPictureURLLength = 2048

// SafePictureURL returns the URL if it is an https URL with a DNS host name
// (no IP literal, no localhost, no userinfo, no fragment), otherwise "".
// The relying party may fetch it server-side (Gitea UPDATE_AVATAR), so this
// reduces SSRF exposure; DNS-based tricks still need an egress policy there.
func SafePictureURL(raw string) string {
	if raw == "" || len(raw) > maxPictureURLLength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return ""
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil || strings.Contains(host, "%") {
		return ""
	}
	lh := strings.ToLower(strings.TrimSuffix(host, "."))
	if lh == "localhost" || strings.HasSuffix(lh, ".localhost") || strings.HasSuffix(lh, ".local") ||
		strings.HasSuffix(lh, ".internal") || strings.HasSuffix(lh, ".svc") || strings.HasSuffix(lh, ".cluster.local") ||
		!strings.Contains(lh, ".") {
		return ""
	}
	if p := u.Port(); p != "" && p != "443" {
		return ""
	}
	u.Fragment = ""
	return u.String()
}
