package githubsubs

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestIntegrationLiveGitHub is opt-in because it consumes GitHub API quota.
// Set both GITHUB_SUBS_CONFIG and GITHUB_SUBS_DOMAIN to run it.
func TestIntegrationLiveGitHub(t *testing.T) {
	configPath := strings.TrimSpace(os.Getenv("GITHUB_SUBS_CONFIG"))
	domain := strings.TrimSpace(os.Getenv("GITHUB_SUBS_DOMAIN"))
	if configPath == "" || domain == "" {
		t.Skip("set GITHUB_SUBS_CONFIG and GITHUB_SUBS_DOMAIN to run the live GitHub test")
	}

	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read provider config: %v", err)
	}
	var providers map[string][]string
	if err := yaml.Unmarshal(contents, &providers); err != nil {
		t.Fatalf("decode provider config: %v", err)
	}
	tokens := providers["github"]
	if len(tokens) == 0 {
		t.Fatal("provider config contains no GitHub tokens")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	results, err := New(tokens).Enumerate(ctx, domain)
	if err != nil {
		t.Fatalf("enumerate GitHub subdomains: %v", err)
	}
	sort.Strings(results)
	t.Logf("GitHub extraction found %d unique subdomains for %s", len(results), domain)
	for _, result := range results {
		t.Log(result)
	}
}
