package nostr

import (
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"
)

// Gitea's username rule (modules/validation/helpers.go).
var giteaUsername = regexp.MustCompile(`^[\da-zA-Z][-.\w]*$`)

func TestUsernameDeterministicAndValid(t *testing.T) {
	sk := gonostr.GeneratePrivateKey()
	pk, _ := gonostr.GetPublicKey(sk)
	u1, err := Username(pk)
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := Username(pk)
	if u1 != u2 {
		t.Fatal("username not deterministic")
	}
	if len(u1) != UsernameLength || !strings.HasPrefix(u1, "npub1") || len(u1) > 40 {
		t.Fatalf("bad username %q", u1)
	}
	if !giteaUsername.MatchString(u1) {
		t.Fatalf("username %q is not a valid Gitea username", u1)
	}
	if !strings.HasPrefix(PubkeyToNpub(pk), u1) {
		t.Fatal("username is not an npub prefix")
	}
	if _, err := Username("not-a-key"); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := Username(strings.ToUpper(pk)); err == nil {
		t.Fatal("uppercase hex accepted")
	}
}

func TestPlaceholderEmail(t *testing.T) {
	pk, _ := gonostr.GetPublicKey(gonostr.GeneratePrivateKey())
	e, err := PlaceholderEmail(pk, "nostr.invalid")
	if err != nil {
		t.Fatal(err)
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e {
		t.Fatalf("placeholder email %q not RFC 5322 valid: %v", e, err)
	}
	local, domain, _ := strings.Cut(e, "@")
	if local != PubkeyToNpub(pk) || domain != "nostr.invalid" || len(local) > 64 {
		t.Fatalf("unexpected placeholder %q", e)
	}
}

func TestSafePictureURL(t *testing.T) {
	ok := []string{
		"https://example.com/a.png",
		"https://cdn.example.org:443/x.jpg?size=1",
	}
	bad := []string{
		"", "http://example.com/a.png", "https://127.0.0.1/a.png", "https://[::1]/a.png",
		"https://localhost/a.png", "https://169.254.169.254/latest", "https://user:pw@example.com/a",
		"javascript:alert(1)", "data:image/png;base64,AAAA", "https://intranet/a.png",
		"https://example.com:8443/a.png", "https://kubernetes.default.svc/a", "https://foo.internal/a",
		"https://" + strings.Repeat("a", 2100) + ".com/",
	}
	for _, u := range ok {
		if SafePictureURL(u) == "" {
			t.Errorf("rejected %q", u)
		}
	}
	for _, u := range bad {
		if SafePictureURL(u) != "" {
			t.Errorf("accepted %q", u)
		}
	}
}

func TestSanitizeDisplayName(t *testing.T) {
	cases := map[string]string{
		"  Alice  ":              "Alice",
		"Al\u202eice":                 "Alice", // RTL override stripped
		"Bob\u200b\u0000\n Smith":     "Bob Smith",
		strings.Repeat("x", 200): strings.Repeat("x", 64),
		"\xff\xfeMallory":        "Mallory",
	}
	for in, want := range cases {
		if got := SanitizeDisplayName(in); got != want {
			t.Errorf("SanitizeDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPublicAddr(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.100",
		"100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd7a:115c:a1e0::1", "::ffff:127.0.0.1", "224.0.0.1",
		"198.18.0.1", "::",
	} {
		if IsPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
}

func TestNormalizeRelayURL(t *testing.T) {
	if normalizeRelayURL("wss://relay.example.com/", false) == "" {
		t.Error("valid wss relay rejected")
	}
	for _, u := range []string{
		"ws://relay.example.com/", "wss://10.0.0.1/", "wss://localhost/", "https://relay.example.com/",
		"wss://user@relay.example.com/", "wss://kubernetes.default.svc/", "wss://relay/", "wss://[::1]:7777/",
		"wss://" + strings.Repeat("a", 300) + ".com",
	} {
		if normalizeRelayURL(u, false) != "" {
			t.Errorf("user relay %q accepted", u)
		}
	}
	if normalizeRelayURL("ws://127.0.0.1:7777/", true) == "" {
		t.Error("operator ws relay rejected")
	}
}
