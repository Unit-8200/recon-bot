// Package config loads and validates the bot's YAML configuration.
package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultImage               = "discord-puredns:2.1.1"
	defaultPassiveThreshold    = 1000
	defaultPureDNSRateLimit    = 5000
	defaultPureDNSTimeout      = 2 * time.Hour
	defaultCaduceusTimeout     = 4 * time.Hour
	persistentDirectoryName    = "recon-bot"
	persistentDatabaseName     = "recon.db"
	legacyDatabaseRelativePath = "data/recon.db"
)

// Config contains the settings needed to assemble the application.
type Config struct {
	DiscordToken            string
	DiscordGuildID          string
	SubfinderProviderConfig string
	DatabasePath            string
	LegacyDatabasePath      string
	PureDNSEnabled          bool
	PureDNSImage            string
	PureDNSPassiveThreshold int
	PureDNSRateLimit        int
	PureDNSTimeout          time.Duration
	CaduceusImage           string
	CaduceusTimeout         time.Duration
}

type fileConfig struct {
	Discord struct {
		Token   string `yaml:"token"`
		GuildID string `yaml:"guild_id"`
	} `yaml:"discord"`
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	Subfinder struct {
		ProviderConfig string `yaml:"provider_config"`
	} `yaml:"subfinder"`
	PureDNS struct {
		Enabled          bool   `yaml:"enabled"`
		Image            string `yaml:"image"`
		PassiveThreshold *int   `yaml:"passive_threshold"`
		RateLimit        *int   `yaml:"rate_limit"`
		Timeout          string `yaml:"timeout"`
	} `yaml:"puredns"`
	Caduceus struct {
		Image   string `yaml:"image"`
		Timeout string `yaml:"timeout"`
	} `yaml:"caduceus"`
}

// Load reads a YAML file and validates the complete runtime configuration.
func Load(path string) (Config, error) {
	config, err := load(path)
	if err != nil {
		return Config{}, err
	}
	if config.DiscordToken == "" {
		return Config{}, fmt.Errorf("discord.token is required")
	}
	return config, nil
}

// LoadDatabasePaths reads only the paths needed by offline migration commands.
func LoadDatabasePaths(path string) (string, string, error) {
	config, err := load(path)
	if err != nil {
		return "", "", err
	}
	return config.DatabasePath, config.LegacyDatabasePath, nil
}

func load(path string) (Config, error) {
	configPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("configuration file path is required")
	}
	file, err := os.Open(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration file %s: %w", configPath, err)
	}
	defer file.Close()

	var raw fileConfig
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode configuration file %s: %w", configPath, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("configuration file %s contains multiple YAML documents", configPath)
		}
		return Config{}, fmt.Errorf("decode configuration file %s: %w", configPath, err)
	}

	baseDirectory := filepath.Dir(configPath)
	databasePath, legacyDatabasePath, err := databasePaths(baseDirectory, raw.Database.Path)
	if err != nil {
		return Config{}, err
	}
	providerConfig, err := optionalPath(baseDirectory, raw.Subfinder.ProviderConfig)
	if err != nil {
		return Config{}, fmt.Errorf("resolve subfinder.provider_config: %w", err)
	}
	threshold := defaultPassiveThreshold
	if raw.PureDNS.PassiveThreshold != nil {
		threshold = *raw.PureDNS.PassiveThreshold
	}
	if threshold < 0 {
		return Config{}, fmt.Errorf("puredns.passive_threshold must be non-negative")
	}
	rateLimit := defaultPureDNSRateLimit
	if raw.PureDNS.RateLimit != nil {
		rateLimit = *raw.PureDNS.RateLimit
	}
	if rateLimit < 0 {
		return Config{}, fmt.Errorf("puredns.rate_limit must be non-negative")
	}
	pureDNSTimeout, err := duration(raw.PureDNS.Timeout, defaultPureDNSTimeout, "puredns.timeout")
	if err != nil {
		return Config{}, err
	}
	caduceusTimeout, err := duration(raw.Caduceus.Timeout, defaultCaduceusTimeout, "caduceus.timeout")
	if err != nil {
		return Config{}, err
	}
	pureDNSImage := valueOrDefault(raw.PureDNS.Image, defaultImage)

	return Config{
		DiscordToken:            strings.TrimSpace(raw.Discord.Token),
		DiscordGuildID:          strings.TrimSpace(raw.Discord.GuildID),
		SubfinderProviderConfig: providerConfig,
		DatabasePath:            databasePath,
		LegacyDatabasePath:      legacyDatabasePath,
		PureDNSEnabled:          raw.PureDNS.Enabled,
		PureDNSImage:            pureDNSImage,
		PureDNSPassiveThreshold: threshold,
		PureDNSRateLimit:        rateLimit,
		PureDNSTimeout:          pureDNSTimeout,
		CaduceusImage:           valueOrDefault(raw.Caduceus.Image, pureDNSImage),
		CaduceusTimeout:         caduceusTimeout,
	}, nil
}

func databasePaths(baseDirectory, configured string) (string, string, error) {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		path, err := resolvePath(baseDirectory, configured)
		return path, "", err
	}
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("find user configuration directory: %w", err)
	}
	legacy, err := filepath.Abs(filepath.FromSlash(legacyDatabaseRelativePath))
	if err != nil {
		return "", "", fmt.Errorf("resolve legacy database path: %w", err)
	}
	return filepath.Join(configDirectory, persistentDirectoryName, persistentDatabaseName), legacy, nil
}

func optionalPath(baseDirectory, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	return resolvePath(baseDirectory, value)
}

func resolvePath(baseDirectory, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("path is required")
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find user home directory: %w", err)
		}
		if value == "~" {
			return home, nil
		}
		value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(baseDirectory, value)
	}
	path, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}

func duration(value string, fallback time.Duration, name string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 2h", name)
	}
	return parsed, nil
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}
