package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/circumspace/gitea-nostr-auth/internal/config"
	"github.com/circumspace/gitea-nostr-auth/internal/handler"
	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
	"github.com/circumspace/gitea-nostr-auth/internal/oidc"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file (falls back to environment variables if missing)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("failed to load config: %v", err)
		}
		log.Printf("config file %q not found, using environment variables", *configPath)
		if cfg, err = config.FromEnv(); err != nil {
			log.Fatalf("invalid environment configuration: %v", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration:\n%v", err)
	}

	var signer *oidc.Signer
	if cfg.OAuth2.SigningKeyFile != "" {
		signer, err = oidc.LoadSigner(cfg.OAuth2.SigningKeyFile)
		if err != nil {
			log.Fatalf("failed to load signing key: %v", err)
		}
	} else {
		log.Printf("no oauth2.signing_key_file configured; generating an ephemeral RSA key (ID tokens are consumed immediately, so restarts are harmless)")
		if signer, err = oidc.GenerateSigner(); err != nil {
			log.Fatalf("failed to generate signing key: %v", err)
		}
	}

	store := oauth2.NewMemoryStore()
	defer store.Close()
	fetcher := nostr.NewFetcher(nostr.Options{
		FallbackRelays: cfg.Nostr.FallbackRelays,
		MaxUserRelays:  cfg.Nostr.MaxUserRelays,
		AllowPrivate:   cfg.Nostr.AllowPrivateRelays,
	})
	if cfg.Nostr.AllowPrivateRelays {
		log.Printf("WARNING: nostr.allow_private_relays is enabled; relay connections to internal addresses are allowed")
	}

	srv := &http.Server{
		Addr:              cfg.Server.Address(),
		Handler:           handler.NewRouter(cfg, store, fetcher, signer),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second, // /userinfo may wait for relays
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	log.Printf("Starting nostr-oauth2-server on %s", srv.Addr)
	log.Printf("Issuer: %s (signing key kid %s)", cfg.Server.BaseURL, signer.KeyID())
	log.Printf("Fallback relays: %v", cfg.Nostr.FallbackRelays)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	case <-ctx.Done():
		log.Printf("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}
}
