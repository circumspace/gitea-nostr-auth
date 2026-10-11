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
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		// Try environment variables if config file not found
		if os.IsNotExist(err) {
			cfg = config.FromEnv()
		} else {
			log.Fatalf("failed to load config: %v", err)
		}
	}

	store := oauth2.NewMemoryStore()
	fetcher := nostr.NewFetcher(cfg.Nostr.FallbackRelays)
	router := handler.NewRouter(cfg, store, fetcher)

	addr := cfg.Server.Address()
	log.Printf("Starting nostr-oauth2-server on %s", addr)
	log.Printf("Base URL: %s", cfg.Server.BaseURL)
	log.Printf("Fallback relays: %v", cfg.Nostr.FallbackRelays)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
