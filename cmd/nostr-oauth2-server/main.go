package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/circumspace/gitea-nostr-auth/internal/config"
	"github.com/circumspace/gitea-nostr-auth/internal/handler"
	"github.com/circumspace/gitea-nostr-auth/internal/nostr"
	"github.com/circumspace/gitea-nostr-auth/internal/oauth2"
	"github.com/circumspace/gitea-nostr-auth/internal/oidc"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		// Try environment variables if config file not found
		if os.IsNotExist(err) {
			if cfg, err = config.FromEnv(); err != nil {
				log.Fatalf("invalid environment configuration: %v", err)
			}
		} else {
			log.Fatalf("failed to load config: %v", err)
		}
	}

	var signer *oidc.Signer
	if cfg.OAuth2.SigningKeyFile != "" {
		signer, err = oidc.LoadSigner(cfg.OAuth2.SigningKeyFile)
		if err != nil {
			log.Fatalf("failed to load signing key: %v", err)
		}
	} else {
		log.Printf("no oauth2.signing_key_file configured; generating an ephemeral RSA key")
		if signer, err = oidc.GenerateSigner(); err != nil {
			log.Fatalf("failed to generate signing key: %v", err)
		}
	}

	store := oauth2.NewMemoryStore()
	fetcher := nostr.NewFetcher(nostr.Options{
		FallbackRelays: cfg.Nostr.FallbackRelays,
		MaxUserRelays:  cfg.Nostr.MaxUserRelays,
		AllowPrivate:   cfg.Nostr.AllowPrivateRelays,
	})
	router := handler.NewRouter(cfg, store, fetcher, signer)

	addr := cfg.Server.Address()
	log.Printf("Starting nostr-oauth2-server on %s", addr)
	log.Printf("Base URL: %s", cfg.Server.BaseURL)
	log.Printf("Fallback relays: %v", cfg.Nostr.FallbackRelays)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
