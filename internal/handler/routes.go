package handler

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/circumspace/gitea-nostr-auth/internal/config"
	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
	"github.com/circumspace/gitea-nostr-auth/internal/oidc"
)

// maxBodyBytes bounds every request body. The largest legitimate body is a
// signed kind-27235 event of a few hundred bytes.
const maxBodyBytes = 16 << 10

// ProfileFetcher looks up Nostr profile metadata.
type ProfileFetcher interface {
	FetchProfile(ctx context.Context, pubkey string) *nostr.ProfileMetadata
}

type Handler struct {
	cfg       *config.Config
	store     oauth2.Store
	fetcher   ProfileFetcher
	signer    *oidc.Signer
	loginTmpl *template.Template
	now       func() time.Time
}

func NewRouter(cfg *config.Config, store oauth2.Store, fetcher ProfileFetcher, signer *oidc.Signer) http.Handler {
	h := &Handler{
		cfg:       cfg,
		store:     store,
		fetcher:   fetcher,
		signer:    signer,
		loginTmpl: template.Must(template.New("login").Parse(loginPageHTML)),
		now:       time.Now,
	}

	r := chi.NewRouter()
	// No RealIP: behind a proxy any client could spoof X-Forwarded-For.
	// No CORS: the login page is same-origin and /token, /userinfo are
	// called server-to-server by the relying party.
	r.Use(accessLog)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(limitBody)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	r.Get("/.well-known/openid-configuration", h.OIDCDiscovery)
	r.Get("/.well-known/jwks.json", h.JWKS)

	r.Get("/authorize", h.Authorize)
	r.Post("/verify", h.Verify)
	r.Post("/token", h.Token)
	r.Get("/userinfo", h.UserInfo)
	r.Post("/userinfo", h.UserInfo)

	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// accessLog logs method, path (without query string), status and duration.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, ww.Status(), time.Since(start).Round(time.Millisecond))
	})
}
