// Package app assembles and runs the bot application.
package app

import (
	"context"
	"fmt"

	"discord-bot/internal/config"
	"discord-bot/internal/discordbot"
	"discord-bot/internal/dnsbruteforce"
	"discord-bot/internal/dnsvalidate"
	"discord-bot/internal/httpprobe"
	"discord-bot/internal/recon"
	"discord-bot/internal/subdomains"
)

// Run builds the application's dependencies and runs until ctx is cancelled.
func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

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

	workflow, err := recon.New(cfg.ResultsDirectory, finder, validator, prober, reconOptions...)
	if err != nil {
		return fmt.Errorf("initialize recon workflow: %w", err)
	}

	bot, err := discordbot.New(cfg.DiscordToken, cfg.DiscordGuildID, workflow)
	if err != nil {
		return err
	}

	return bot.Run(ctx)
}
