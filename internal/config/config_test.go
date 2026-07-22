package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadReadsYAMLDefaultsAndResolvesRelativePaths(t *testing.T) {
	configDirectory := t.TempDir()
	xdgDirectory := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdgDirectory)
	path := writeConfig(t, configDirectory, `
discord:
  token: test-token
  guild_id: "1234"
subfinder:
  provider_config: secrets/providers.yaml
puredns:
  enabled: true
`)

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if config.DiscordToken != "test-token" || config.DiscordGuildID != "1234" {
		t.Fatalf("Discord config = %q, %q", config.DiscordToken, config.DiscordGuildID)
	}
	if config.DatabasePath != filepath.Join(xdgDirectory, "recon-bot", "recon.db") {
		t.Fatalf("database path = %q", config.DatabasePath)
	}
	if config.SubfinderProviderConfig != filepath.Join(configDirectory, "secrets", "providers.yaml") {
		t.Fatalf("provider path = %q", config.SubfinderProviderConfig)
	}
	if !config.PureDNSEnabled || config.PureDNSPassiveThreshold != 1000 || config.PureDNSRateLimit != 5000 || config.PureDNSTimeout != 2*time.Hour {
		t.Fatalf("PureDNS defaults = %+v", config)
	}
	if config.CaduceusImage != defaultImage || config.CaduceusTimeout != 4*time.Hour {
		t.Fatalf("Caduceus defaults = %+v", config)
	}
}

func TestLoadReadsExplicitValuesAndDatabasePath(t *testing.T) {
	directory := t.TempDir()
	path := writeConfig(t, directory, `
discord:
  token: test-token
database:
  path: state/custom.db
puredns:
  image: custom-image
  passive_threshold: 0
  rate_limit: 2500
  timeout: 90m
caduceus:
  image: caduceus-image
  timeout: 3h
`)

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if config.DatabasePath != filepath.Join(directory, "state", "custom.db") || config.LegacyDatabasePath != "" {
		t.Fatalf("database paths = %q, %q", config.DatabasePath, config.LegacyDatabasePath)
	}
	if config.PureDNSImage != "custom-image" || config.PureDNSPassiveThreshold != 0 || config.PureDNSRateLimit != 2500 || config.PureDNSTimeout != 90*time.Minute {
		t.Fatalf("PureDNS config = %+v", config)
	}
	if config.CaduceusImage != "caduceus-image" || config.CaduceusTimeout != 3*time.Hour {
		t.Fatalf("Caduceus config = %+v", config)
	}
}

func TestLoadRejectsMissingTokenUnknownFieldsAndInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "missing token", content: `discord: {guild_id: "1"}`},
		{name: "unknown field", content: "discord:\n  token: test\n  surprise: true\n"},
		{name: "negative threshold", content: "discord:\n  token: test\npuredns:\n  passive_threshold: -1\n"},
		{name: "invalid timeout", content: "discord:\n  token: test\ncaduceus:\n  timeout: forever\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, t.TempDir(), test.content)
			if _, err := Load(path); err == nil {
				t.Fatal("Load() unexpectedly succeeded")
			}
		})
	}
}

func TestLoadDatabasePathsDoesNotRequireDiscordToken(t *testing.T) {
	directory := t.TempDir()
	path := writeConfig(t, directory, "database:\n  path: state/recon.db\n")

	databasePath, legacyPath, err := LoadDatabasePaths(path)
	if err != nil {
		t.Fatalf("LoadDatabasePaths(): %v", err)
	}
	if databasePath != filepath.Join(directory, "state", "recon.db") || legacyPath != "" {
		t.Fatalf("database paths = %q, %q", databasePath, legacyPath)
	}
}

func writeConfig(t *testing.T, directory, contents string) string {
	t.Helper()
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
