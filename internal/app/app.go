// Package app assembles and runs the bot application.
package app

import (
	"context"
	"fmt"

	"discord-bot/internal/config"
	"discord-bot/internal/discordbot"
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
	workflow, err := recon.New(cfg.ResultsDirectory, finder, prober)
	if err != nil {
		return fmt.Errorf("initialize recon workflow: %w", err)
	}

	bot, err := discordbot.New(cfg.DiscordToken, cfg.DiscordGuildID, workflow)
	if err != nil {
		return err
	}

	return bot.Run(ctx)
}
