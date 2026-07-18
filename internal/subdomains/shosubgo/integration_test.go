package shosubgo

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestIntegrationLiveShodan is opt-in because it consumes Shodan query credits.
// Set both SHODAN_SUBS_CONFIG and SHODAN_SUBS_DOMAIN to run it.
func TestIntegrationLiveShodan(t *testing.T) {
	configPath := strings.TrimSpace(os.Getenv("SHODAN_SUBS_CONFIG"))
	domain := strings.TrimSpace(os.Getenv("SHODAN_SUBS_DOMAIN"))
	if configPath == "" || domain == "" {
		t.Skip("set SHODAN_SUBS_CONFIG and SHODAN_SUBS_DOMAIN to run the live Shodan test")
	}

	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read provider config: %v", err)
	}
	var providers map[string][]string
	if err := yaml.Unmarshal(contents, &providers); err != nil {
		t.Fatalf("decode provider config: %v", err)
	}
	keys := providers["shodan"]
	if len(keys) == 0 || strings.TrimSpace(keys[0]) == "" {
		t.Fatal("provider config contains no Shodan API key")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	results, err := New(keys[0]).Enumerate(ctx, domain)
	if err != nil {
		t.Fatalf("enumerate Shodan subdomains: %v", err)
	}
	sort.Strings(results)
	t.Logf("Shodan extraction found %d subdomains for %s", len(results), domain)
	for _, result := range results {
		t.Log(result)
	}
}
