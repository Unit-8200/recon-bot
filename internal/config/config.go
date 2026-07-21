// Package config loads and validates application configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config contains the settings needed to assemble the application.
type Config struct {
	DiscordToken            string
	DiscordGuildID          string
	SubfinderProviderConfig string
	DatabasePath            string
	PureDNSEnabled          bool
	PureDNSImage            string
	PureDNSWordlist         string
	PureDNSResolvers        string
	PureDNSPassiveThreshold int
	PureDNSRateLimit        int
	PureDNSTimeout          time.Duration
	CaduceusImage           string
	CaduceusTimeout         time.Duration
}

// Load reads an optional local .env file and then loads configuration from the
// environment. Existing environment variables take precedence over .env.
func Load() (Config, error) {
	if err := loadEnv(); err != nil {
		return Config{}, err
	}

	pureDNSEnabled, err := parseBool("PUREDNS_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	pureDNSThreshold, err := parseNonNegativeInt("PUREDNS_PASSIVE_THRESHOLD", 1000)
	if err != nil {
		return Config{}, err
	}
	pureDNSRateLimit, err := parseNonNegativeInt("PUREDNS_RATE_LIMIT", 5000)
	if err != nil {
		return Config{}, err
	}
	pureDNSTimeout, err := parseDuration("PUREDNS_TIMEOUT", 2*time.Hour)
	if err != nil {
		return Config{}, err
	}
	caduceusTimeout, err := parseDuration("CADUCEUS_TIMEOUT", 4*time.Hour)
	if err != nil {
		return Config{}, err
	}
	pureDNSImage := envOrDefault("PUREDNS_IMAGE", "discord-puredns:2.1.1")

	config := Config{
		DiscordToken:            strings.TrimSpace(os.Getenv("DISCORD_TOKEN")),
		DiscordGuildID:          strings.TrimSpace(os.Getenv("DISCORD_GUILD_ID")),
		SubfinderProviderConfig: strings.TrimSpace(os.Getenv("SUBFINDER_PROVIDER_CONFIG")),
		DatabasePath:            envOrDefault("DATABASE_PATH", "data/recon.db"),
		PureDNSEnabled:          pureDNSEnabled,
		PureDNSImage:            pureDNSImage,
		PureDNSWordlist:         envOrDefault("PUREDNS_WORDLIST", "data/puredns/n0kovo_subdomains_huge.txt"),
		PureDNSResolvers:        envOrDefault("PUREDNS_RESOLVERS", "data/puredns/resolvers.txt"),
		PureDNSPassiveThreshold: pureDNSThreshold,
		PureDNSRateLimit:        pureDNSRateLimit,
		PureDNSTimeout:          pureDNSTimeout,
		CaduceusImage:           envOrDefault("CADUCEUS_IMAGE", pureDNSImage),
		CaduceusTimeout:         caduceusTimeout,
	}
	if config.DiscordToken == "" {
		return Config{}, fmt.Errorf("DISCORD_TOKEN is required")
	}
	return config, nil
}

// LoadDatabasePath loads only the settings required by offline database commands.
func LoadDatabasePath() (string, error) {
	if err := loadEnv(); err != nil {
		return "", err
	}
	return envOrDefault("DATABASE_PATH", "data/recon.db"), nil
}

func loadEnv() error {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load .env: %w", err)
	}
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func parseBool(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false: %w", name, err)
	}
	return parsed, nil
}

func parseNonNegativeInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return parsed, nil
}

func parseDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration such as 2h", name)
	}
	return parsed, nil
}
