package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/circumspace/gitea-nostr-auth/internal/config"
	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
)

func NewRouter(cfg *config.Config, store oauth2.Store, fetcher *nostr.Fetcher) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	h := &Handler{
		cfg:     cfg,
		store:   store,
		fetcher: fetcher,
	}

	// OIDC Discovery
	r.Get("/.well-known/openid-configuration", h.OIDCDiscovery)

	// OAuth2 endpoints
	r.Get("/authorize", h.Authorize)
	r.Post("/verify", h.Verify)
	r.Post("/token", h.Token)
	r.Get("/userinfo", h.UserInfo)

	// JWKS endpoint (required for OIDC)
	r.Get("/.well-known/jwks.json", h.JWKS)

	return r
}

type Handler struct {
	cfg     *config.Config
	store   oauth2.Store
	fetcher *nostr.Fetcher
}
