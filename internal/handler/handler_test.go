package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"

	"github.com/circumspace/gitea-nostr-auth/internal/config"
	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
	"github.com/circumspace/gitea-nostr-auth/internal/oidc"
)

const (
	testSecret   = "0123456789abcdef0123456789abcdef"
	testRedirect = "https://git.example.com/user/oauth2/nostr/callback"
)

// fakeFetcher returns an attacker-controlled profile.
type fakeFetcher struct{ p *nostr.ProfileMetadata }

func (f fakeFetcher) FetchProfile(_ context.Context, pk string) *nostr.ProfileMetadata {
	if f.p == nil {
		return nil
	}
	cp := *f.p
	cp.Pubkey = pk
	return &cp
}

type env struct {
	t      *testing.T
	srv    *httptest.Server
	cfg    *config.Config
	store  *oauth2.MemoryStore
	signer *oidc.Signer
	client *http.Client // browser with cookie jar, no redirects followed
}

func newEnv(t *testing.T, mutate ...func(*config.Config)) *env {
	t.Helper()
	cfg := &config.Config{}
	cfg.OAuth2.Clients = []config.ClientConfig{
		{ClientID: "gitea", ClientSecret: testSecret, RedirectURIs: []string{testRedirect}},
		{ClientID: "strict", ClientSecret: testSecret, RedirectURIs: []string{testRedirect}, RequirePKCE: true},
	}
	for _, m := range mutate {
		m(cfg)
	}
	store := oauth2.NewMemoryStore()
	t.Cleanup(store.Close)
	signer, err := oidc.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, cfg: cfg, store: store, signer: signer}
	// BaseURL must be known before the router is built, so start unstarted.
	e.srv = httptest.NewUnstartedServer(nil)
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	cfg.Server.BaseURL = e.srv.URL
	if cfg.Nostr.ChallengeTTL == 0 {
		cfg.Nostr.ChallengeTTL = time.Minute
	}
	cfg.OAuth2.CodeTTL = time.Minute
	cfg.OAuth2.AccessTokenTTL = time.Minute
	cfg.OAuth2.IDTokenTTL = time.Minute
	cfg.Nostr.EmailDomain = "nostr.invalid"
	e.srv.Config.Handler = NewRouter(cfg, store, fakeFetcher{p: &nostr.ProfileMetadata{
		Name: "admin", DisplayName: "Daniel\u202e", Nip05: "admin@git.example.com",
		Picture: "https://example.com/p.png",
	}}, signer)

	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return e
}

var challengeRE = regexp.MustCompile(`const challenge = "([0-9a-f]{64})"`)
var statementRE = regexp.MustCompile(`const statement = "([^"]*)"`)

type authz struct {
	challenge string
	statement string
}

func (e *env) authorize(params url.Values) (*http.Response, authz) {
	e.t.Helper()
	q := url.Values{"client_id": {"gitea"}, "redirect_uri": {testRedirect}, "response_type": {"code"}, "scope": {"openid profile email"}, "state": {"st"}}
	for k, v := range params {
		q[k] = v
	}
	resp, err := e.client.Get(e.srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var a authz
	if m := challengeRE.FindSubmatch(body); m != nil {
		a.challenge = string(m[1])
	}
	if m := statementRE.FindSubmatch(body); m != nil {
		var s string
		_ = json.Unmarshal([]byte(`"`+string(m[1])+`"`), &s)
		a.statement = s
	}
	return resp, a
}

func (e *env) loginEvent(sk string, a authz) gonostr.Event {
	ev := gonostr.Event{
		Kind:      KindHTTPAuth,
		CreatedAt: gonostr.Now(),
		Tags:      gonostr.Tags{{"u", e.srv.URL + "/verify"}, {"method", "POST"}, {"challenge", a.challenge}},
		Content:   a.statement,
	}
	if err := ev.Sign(sk); err != nil {
		e.t.Fatal(err)
	}
	return ev
}

func (e *env) verify(c *http.Client, ev any) (int, VerifyResponse) {
	e.t.Helper()
	b, _ := json.Marshal(ev)
	resp, err := c.Post(e.srv.URL+"/verify", "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var vr VerifyResponse
	_ = json.NewDecoder(resp.Body).Decode(&vr)
	return resp.StatusCode, vr
}

func codeFrom(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(redirect, testRedirect+"?") {
		t.Fatalf("redirect %q does not go to the registered redirect_uri", redirect)
	}
	if u.Query().Get("state") != "st" {
		t.Fatalf("state not echoed: %q", redirect)
	}
	return u.Query().Get("code")
}

func (e *env) token(form url.Values, basic bool) (int, TokenResponse) {
	e.t.Helper()
	if form.Get("grant_type") == "" {
		form.Set("grant_type", "authorization_code")
	}
	if form.Get("redirect_uri") == "" {
		form.Set("redirect_uri", testRedirect)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth("gitea", testSecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		e.t.Errorf("token response Cache-Control = %q", cc)
	}
	var tr TokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&tr)
	return resp.StatusCode, tr
}

func (e *env) userinfo(token string) (int, map[string]any) {
	req, _ := http.NewRequest("GET", e.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (e *env) parseIDToken(tok string) map[string]any {
	e.t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		e.t.Fatalf("bad id token %q", tok)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(e.signer.PublicKey(), crypto.SHA256, h[:], sig); err != nil {
		e.t.Fatalf("id token signature invalid: %v", err)
	}
	var hdr map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr["alg"] != "RS256" || hdr["kid"] != e.signer.KeyID() {
		e.t.Fatalf("bad header %v", hdr)
	}
	var claims map[string]any
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(pb, &claims)
	return claims
}

func newKey(t *testing.T) (sk, pk string) {
	sk = gonostr.GeneratePrivateKey()
	pk, err := gonostr.GetPublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	return sk, pk
}

// login runs the browser part of the flow and returns the code.
func (e *env) login(sk string, params url.Values) string {
	e.t.Helper()
	resp, a := e.authorize(params)
	if resp.StatusCode != http.StatusOK || a.challenge == "" {
		e.t.Fatalf("authorize: status %d", resp.StatusCode)
	}
	status, vr := e.verify(e.client, e.loginEvent(sk, a))
	if status != http.StatusOK || !vr.Success {
		e.t.Fatalf("verify failed: %d %+v", status, vr)
	}
	return codeFrom(e.t, vr.RedirectURL)
}

func TestFullFlowAndClaims(t *testing.T) {
	e := newEnv(t)
	sk, pk := newKey(t)
	code := e.login(sk, url.Values{"nonce": {"n-123"}})

	status, tr := e.token(url.Values{"code": {code}}, true)
	if status != http.StatusOK || tr.AccessToken == "" || tr.TokenType != "Bearer" {
		t.Fatalf("token: %d %+v", status, tr)
	}
	claims := e.parseIDToken(tr.IDToken)
	username, _ := nostr.Username(pk)
	npub := nostr.PubkeyToNpub(pk)
	want := map[string]any{
		"iss": e.srv.URL, "sub": pk, "aud": "gitea", "azp": "gitea", "nonce": "n-123",
		"preferred_username": username, "nickname": username,
		"email": npub + "@nostr.invalid", "email_verified": false,
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("id token %s = %v, want %v", k, claims[k], v)
		}
	}
	now := float64(time.Now().Unix())
	if exp, _ := claims["exp"].(float64); exp <= now || exp > now+120 {
		t.Errorf("bad exp %v", claims["exp"])
	}
	if iat, _ := claims["iat"].(float64); iat > now+1 || iat < now-60 {
		t.Errorf("bad iat %v", claims["iat"])
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Error("missing auth_time")
	}

	// Userinfo: identity claims are deterministic even though the profile
	// claims name "admin" and nip05 "admin@git.example.com".
	status, ui := e.userinfo(tr.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("userinfo %d", status)
	}
	if ui["sub"] != pk || ui["preferred_username"] != username || ui["nickname"] != username ||
		ui["email"] != npub+"@nostr.invalid" || ui["email_verified"] != false {
		t.Fatalf("userinfo identity claims not deterministic: %v", ui)
	}
	if ui["name"] != "Daniel" {
		t.Errorf("display name not sanitised: %q", ui["name"])
	}
	if ui["picture"] != "https://example.com/p.png" {
		t.Errorf("picture %v", ui["picture"])
	}
	for _, k := range []string{"profile", "website"} {
		if _, ok := ui[k]; ok {
			t.Errorf("unexpected claim %s", k)
		}
	}
}

func TestClientSecretPostAuth(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	code := e.login(sk, nil)
	status, tr := e.token(url.Values{"code": {code}, "client_id": {"gitea"}, "client_secret": {testSecret}}, false)
	if status != http.StatusOK || tr.AccessToken == "" {
		t.Fatalf("client_secret_post failed: %d %+v", status, tr)
	}
}

func TestTokenClientAuthFailures(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	code := e.login(sk, nil)
	cases := []struct {
		name   string
		form   url.Values
		basic  bool
		status int
	}{
		{"wrong secret", url.Values{"code": {code}, "client_id": {"gitea"}, "client_secret": {"nope"}}, false, 400},
		{"empty secret", url.Values{"code": {code}, "client_id": {"gitea"}}, false, 400},
		{"unknown client", url.Values{"code": {code}, "client_id": {"x"}, "client_secret": {testSecret}}, false, 400},
		{"both methods", url.Values{"code": {code}, "client_secret": {testSecret}}, true, 400},
	}
	for _, c := range cases {
		status, tr := e.token(c.form, c.basic)
		if status != c.status || tr.AccessToken != "" {
			t.Errorf("%s: status %d token %q", c.name, status, tr.AccessToken)
		}
	}
	// The code was never redeemed, so it still works.
	if status, _ := e.token(url.Values{"code": {code}}, true); status != 200 {
		t.Fatalf("valid redemption failed after auth failures: %d", status)
	}
}

func TestCodeReuseRevokes(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	code := e.login(sk, nil)
	status, tr := e.token(url.Values{"code": {code}}, true)
	if status != 200 {
		t.Fatalf("first redemption %d", status)
	}
	status2, tr2 := e.token(url.Values{"code": {code}}, true)
	if status2 != 400 || tr2.Error != "invalid_grant" || tr2.AccessToken != "" {
		t.Fatalf("code reuse allowed: %d %+v", status2, tr2)
	}
	if s, _ := e.userinfo(tr.AccessToken); s != http.StatusUnauthorized {
		t.Fatalf("token from reused code still valid: %d", s)
	}
}

func TestTokenRedirectURIMismatch(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	code := e.login(sk, nil)
	status, tr := e.token(url.Values{"code": {code}, "redirect_uri": {testRedirect + "x"}}, true)
	if status != 400 || tr.Error != "invalid_grant" {
		t.Fatalf("redirect mismatch accepted: %d %+v", status, tr)
	}
}

func TestAuthorizeRejectsBadRedirectWithoutRedirecting(t *testing.T) {
	e := newEnv(t)
	for _, ru := range []string{"https://evil.example.com/cb", testRedirect + "/", testRedirect + "?a=b", ""} {
		resp, a := e.authorize(url.Values{"redirect_uri": {ru}})
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || a.challenge != "" {
			t.Errorf("redirect_uri %q: status %d location %q", ru, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	resp, _ := e.authorize(url.Values{"client_id": {"unknown"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown client: %d", resp.StatusCode)
	}
}

func TestAuthorizeErrorsRedirectToValidatedURI(t *testing.T) {
	e := newEnv(t)
	cases := map[string]url.Values{
		"unsupported_response_type": {"response_type": {"token"}},
		"invalid_scope":             {"scope": {"profile"}},
		"invalid_request":           {"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"plain"}},
		"login_required":            {"prompt": {"none"}},
	}
	for wantErr, params := range cases {
		resp, _ := e.authorize(params)
		loc := resp.Header.Get("Location")
		u, _ := url.Parse(loc)
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, testRedirect+"?") ||
			u.Query().Get("error") != wantErr || u.Query().Get("state") != "st" {
			t.Errorf("%s: status %d location %q", wantErr, resp.StatusCode, loc)
		}
	}
}

func pkcePair() (verifier, challenge string) {
	verifier = strings.Repeat("v", 20) + "-._~" + strings.Repeat("x", 30)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestPKCE(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	verifier, challenge := pkcePair()
	pkce := url.Values{"code_challenge": {challenge}, "code_challenge_method": {"S256"}}

	code := e.login(sk, pkce)
	if s, tr := e.token(url.Values{"code": {code}}, true); s != 400 || tr.Error != "invalid_grant" {
		t.Errorf("missing verifier accepted: %d", s)
	}
	code = e.login(sk, pkce)
	if s, _ := e.token(url.Values{"code": {code}, "code_verifier": {strings.Repeat("w", 50)}}, true); s != 400 {
		t.Errorf("wrong verifier accepted: %d", s)
	}
	code = e.login(sk, pkce)
	if s, tr := e.token(url.Values{"code": {code}, "code_verifier": {verifier}}, true); s != 200 || tr.AccessToken == "" {
		t.Errorf("correct verifier rejected: %d %+v", s, tr)
	}
	// Downgrade: verifier without challenge.
	code = e.login(sk, nil)
	if s, _ := e.token(url.Values{"code": {code}, "code_verifier": {verifier}}, true); s != 400 {
		t.Errorf("verifier without challenge accepted: %d", s)
	}
	// Client with require_pkce.
	resp, _ := e.authorize(url.Values{"client_id": {"strict"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("require_pkce client without challenge: %d %q", resp.StatusCode, loc)
	}
}

func TestVerifyRejections(t *testing.T) {
	e := newEnv(t)
	sk, pk := newKey(t)
	otherSK, _ := newKey(t)

	type mut func(a authz) any
	resign := func(f func(ev *gonostr.Event)) mut {
		return func(a authz) any {
			ev := e.loginEvent(sk, a)
			f(&ev)
			_ = ev.Sign(sk)
			return ev
		}
	}
	cases := map[string]struct {
		m      mut
		status int
	}{
		"bad signature": {func(a authz) any {
			ev := e.loginEvent(sk, a)
			ev.Sig = strings.Repeat("0", 128)
			return ev
		}, 400},
		"tampered after signing": {func(a authz) any {
			ev := e.loginEvent(sk, a)
			ev.Content += " "
			return ev
		}, 400},
		"wrong pubkey": {func(a authz) any {
			ev := e.loginEvent(otherSK, a)
			ev.PubKey = pk // claim to be pk with otherSK's signature
			return ev
		}, 400},
		"forged id (signature from another event)": {func(a authz) any {
			note := gonostr.Event{Kind: 1, Content: "gm", CreatedAt: gonostr.Timestamp(1700000000)}
			_ = note.Sign(sk)
			ev := e.loginEvent(sk, a)
			ev.ID, ev.Sig = note.ID, note.Sig
			return ev
		}, 400},
		"wrong kind":      {resign(func(ev *gonostr.Event) { ev.Kind = 1 }), 400},
		"too old":         {resign(func(ev *gonostr.Event) { ev.CreatedAt = gonostr.Timestamp(time.Now().Add(-2 * time.Minute).Unix()) }), 400},
		"future":          {resign(func(ev *gonostr.Event) { ev.CreatedAt = gonostr.Timestamp(time.Now().Add(5 * time.Minute).Unix()) }), 400},
		"wrong u tag":     {resign(func(ev *gonostr.Event) { ev.Tags[0][1] = "https://other.example.com/verify" }), 400},
		"GET method":      {resign(func(ev *gonostr.Event) { ev.Tags[1][1] = "GET" }), 400},
		"wrong content":   {resign(func(ev *gonostr.Event) { ev.Content = "" }), 400},
		"unknown nonce":   {resign(func(ev *gonostr.Event) { ev.Tags[2][1] = strings.Repeat("a", 64) }), 400},
		"two challenges":  {resign(func(ev *gonostr.Event) { ev.Tags = append(ev.Tags, gonostr.Tag{"challenge", "x"}) }), 400},
		"no challenge":    {resign(func(ev *gonostr.Event) { ev.Tags = ev.Tags[:2] }), 400},
		"not json object": {func(authz) any { return "x" }, 400},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, a := e.authorize(nil)
			status, vr := e.verify(e.client, c.m(a))
			if status != c.status || vr.Success || vr.RedirectURL != "" {
				t.Fatalf("status %d resp %+v", status, vr)
			}
			t.Logf("rejected: %s", vr.Error)
		})
	}
}

func TestVerifyReplay(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	_, a := e.authorize(nil)
	ev := e.loginEvent(sk, a)
	if s, vr := e.verify(e.client, ev); s != 200 || !vr.Success {
		t.Fatalf("first verify failed: %d %+v", s, vr)
	}
	// Same browser needs a new binding cookie path; replay from a second
	// authorize in the same jar to keep the cookie valid.
	e.authorize(nil)
	if s, vr := e.verify(e.client, ev); s != 400 || vr.Success {
		t.Fatalf("replayed event accepted: %d %+v", s, vr)
	}
}

func TestVerifyExpiredChallenge(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Nostr.ChallengeTTL = 300 * time.Millisecond })
	sk, _ := newKey(t)
	_, a := e.authorize(nil)
	time.Sleep(400 * time.Millisecond)
	if s, vr := e.verify(e.client, e.loginEvent(sk, a)); s != 400 || vr.Success {
		t.Fatalf("expired challenge accepted: %d %+v", s, vr)
	}
}

func TestVerifyRequiresBindingCookie(t *testing.T) {
	e := newEnv(t)
	sk, _ := newKey(t)
	_, a := e.authorize(nil)
	ev := e.loginEvent(sk, a)
	// A different browser (no cookie) cannot complete the challenge.
	other := &http.Client{}
	if s, vr := e.verify(other, ev); s != http.StatusForbidden || vr.Success {
		t.Fatalf("verify without binding cookie: %d %+v", s, vr)
	}
	// And the challenge is burnt.
	if s, _ := e.verify(e.client, ev); s != 400 {
		t.Fatalf("challenge reusable after failed binding: %d", s)
	}
}

func TestVerifyContentType(t *testing.T) {
	e := newEnv(t)
	resp, err := e.client.Post(e.srv.URL+"/verify", "text/plain", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t)
	big := bytes.Repeat([]byte("a"), 1<<20)
	resp, err := e.client.Post(e.srv.URL+"/verify", "application/json", bytes.NewReader(append([]byte(`{"content":"`), big...)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("oversized body: status %d", resp.StatusCode)
	}
}

func TestUserinfoRejectsBadTokens(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "nope", strings.Repeat("a", 64)} {
		if s, _ := e.userinfo(tok); s != http.StatusUnauthorized {
			t.Errorf("token %q: status %d", tok, s)
		}
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var d OIDCConfiguration
	_ = json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if d.Issuer != e.srv.URL || d.AuthorizationEndpoint != e.srv.URL+"/authorize" ||
		d.TokenEndpoint != e.srv.URL+"/token" || d.UserInfoEndpoint != e.srv.URL+"/userinfo" ||
		d.JwksURI != e.srv.URL+"/.well-known/jwks.json" {
		t.Fatalf("bad discovery %+v", d)
	}
	if len(d.CodeChallengeMethodsSupported) != 1 || d.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("code_challenge_methods_supported %v", d.CodeChallengeMethodsSupported)
	}
	resp, _ = http.Get(d.JwksURI)
	var set oidc.JWKSet
	_ = json.NewDecoder(resp.Body).Decode(&set)
	resp.Body.Close()
	if len(set.Keys) != 1 || set.Keys[0].Kid != e.signer.KeyID() {
		t.Fatalf("bad jwks %+v", set)
	}
}

func TestNoCORSAndSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("OPTIONS", e.srv.URL+"/verify", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS preflight allowed")
	}

	resp, _ = e.authorize(nil)
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'nonce-") {
		t.Errorf("CSP %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Error("missing security headers")
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "nostr-auth-binding" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("binding cookie missing or weak: %+v", cookie)
	}
}
