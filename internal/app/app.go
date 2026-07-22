// Package app assembles and runs the bot application.
package app

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/config"
	"github.com/Unit-8200/recon-bot/internal/database"
	"github.com/Unit-8200/recon-bot/internal/discordbot"
	"github.com/Unit-8200/recon-bot/internal/migration"
	"github.com/Unit-8200/recon-bot/internal/modules/dnsbruteforce"
	"github.com/Unit-8200/recon-bot/internal/modules/dnsvalidate"
	"github.com/Unit-8200/recon-bot/internal/modules/httpprobe"
	"github.com/Unit-8200/recon-bot/internal/modules/ipscan"
	"github.com/Unit-8200/recon-bot/internal/modules/subdomains"
	"github.com/Unit-8200/recon-bot/internal/recon"
	"github.com/Unit-8200/recon-bot/internal/scanqueue"
)

// Run builds the application's dependencies from configPath and runs until ctx is cancelled.
func Run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if copied, copyErr := database.CopyIfMissing(ctx, cfg.LegacyDatabasePath, cfg.DatabasePath); copyErr != nil {
		return fmt.Errorf("relocate repository database: %w", copyErr)
	} else if copied {
		log.Printf("copied legacy database to persistent path %s", cfg.DatabasePath)
	}
	store, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer store.Close()
	log.Printf("using SQLite database %s", cfg.DatabasePath)

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

// Migrate additively imports a legacy results folder or previous SQLite
// database into the configured database.
func Migrate(ctx context.Context, configPath string, source migration.Source) (migration.Report, error) {
	databasePath, legacyDatabasePath, err := config.LoadDatabasePaths(configPath)
	if err != nil {
		return migration.Report{}, err
	}
	// When the explicitly selected database is also the legacy repository
	// database, import it normally instead of first copying it byte-for-byte.
	// That gives its native runs stable import identities for future reruns.
	if source.Database == "" || !samePath(source.Database, legacyDatabasePath) {
		if copied, copyErr := database.CopyIfMissing(ctx, legacyDatabasePath, databasePath); copyErr != nil {
			return migration.Report{}, fmt.Errorf("relocate repository database: %w", copyErr)
		} else if copied {
			log.Printf("copied legacy database to persistent path %s", databasePath)
		}
	}
	store, err := database.Open(databasePath)
	if err != nil {
		return migration.Report{}, fmt.Errorf("initialize database: %w", err)
	}
	defer store.Close()
	log.Printf("using SQLite database %s", databasePath)
	return migration.Import(ctx, store, source)
}

func samePath(left, right string) bool {
	left, leftErr := filepath.Abs(strings.TrimSpace(left))
	right, rightErr := filepath.Abs(strings.TrimSpace(right))
	return leftErr == nil && rightErr == nil && left == right
}
