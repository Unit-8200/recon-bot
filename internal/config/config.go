// Package config loads and validates application configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config contains the settings needed to assemble the application.
type Config struct {
	DiscordToken            string
	DiscordGuildID          string
	SubfinderProviderConfig string
	ResultsDirectory        string
}

// Load reads an optional local .env file and then loads configuration from the
// environment. Existing environment variables take precedence over .env.
func Load() (Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("load .env: %w", err)
	}

	config := Config{
		DiscordToken:            strings.TrimSpace(os.Getenv("DISCORD_TOKEN")),
		DiscordGuildID:          strings.TrimSpace(os.Getenv("DISCORD_GUILD_ID")),
		SubfinderProviderConfig: strings.TrimSpace(os.Getenv("SUBFINDER_PROVIDER_CONFIG")),
		ResultsDirectory:        strings.TrimSpace(os.Getenv("RESULTS_DIR")),
	}
	if config.DiscordToken == "" {
		return Config{}, fmt.Errorf("DISCORD_TOKEN is required")
	}
	if config.ResultsDirectory == "" {
		config.ResultsDirectory = "results"
	}

	return config, nil
}
