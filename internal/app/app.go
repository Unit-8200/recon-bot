// Package app assembles and runs the bot application.
package app

import (
	"context"
	"fmt"

	"discord-bot/internal/config"
	"discord-bot/internal/database"
	"discord-bot/internal/discordbot"
	"discord-bot/internal/migration"
	"discord-bot/internal/modules/dnsbruteforce"
	"discord-bot/internal/modules/dnsvalidate"
	"discord-bot/internal/modules/httpprobe"
	"discord-bot/internal/modules/ipscan"
	"discord-bot/internal/modules/subdomains"
	"discord-bot/internal/recon"
	"discord-bot/internal/scanqueue"
)

// Run builds the application's dependencies and runs until ctx is cancelled.
func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	store, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer store.Close()

	finder, err := subdomains.NewFinderWithOptions(subdomains.FinderOptions{
		ProviderConfig: cfg.SubfinderProviderConfig,
	})
	if err != nil {
		return fmt.Errorf("initialize passive subdomain discovery: %w", err)
	}

	prober, err := httpprobe.New()
	if err != nil {
		return fmt.Errorf("initialize HTTPX: %w", err)
	}
	validator, err := dnsvalidate.New()
	if err != nil {
		return fmt.Errorf("initialize DNSX: %w", err)
	}
	reconOptions := make([]recon.Option, 0, 1)
	if cfg.PureDNSEnabled {
		bruteforcer, pureDNSErr := dnsbruteforce.NewPureDNS(dnsbruteforce.Options{
			Image:     cfg.PureDNSImage,
			Wordlist:  cfg.PureDNSWordlist,
			Resolvers: cfg.PureDNSResolvers,
			RateLimit: cfg.PureDNSRateLimit,
			Timeout:   cfg.PureDNSTimeout,
		})
		if pureDNSErr != nil {
			return fmt.Errorf("initialize PureDNS: %w", pureDNSErr)
		}
		reconOptions = append(reconOptions, recon.WithBruteforcer(bruteforcer, cfg.PureDNSPassiveThreshold))
	}

	workflow, err := recon.New(store, finder, validator, prober, reconOptions...)
	if err != nil {
		return fmt.Errorf("initialize recon workflow: %w", err)
	}
	ipScanner, err := ipscan.NewCaduceus(ipscan.Options{
		Image:   cfg.CaduceusImage,
		Store:   store,
		Timeout: cfg.CaduceusTimeout,
	})
	if err != nil {
		return fmt.Errorf("initialize Caduceus: %w", err)
	}

	queue := scanqueue.New(store)
	bot, err := discordbot.New(cfg.DiscordToken, cfg.DiscordGuildID, workflow, ipScanner, store, queue)
	if err != nil {
		return err
	}

	return bot.Run(ctx)
}

// Migrate imports legacy filesystem runs into the configured SQLite database.
func Migrate(ctx context.Context, folder string) (migration.Report, error) {
	databasePath, err := config.LoadDatabasePath()
	if err != nil {
		return migration.Report{}, err
	}
	store, err := database.Open(databasePath)
	if err != nil {
		return migration.Report{}, fmt.Errorf("initialize database: %w", err)
	}
	defer store.Close()
	return migration.Results(ctx, store, folder)
}
