package subdomains

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func loadProviderConfig(path string) (map[string][]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return map[string][]string{}, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("open subfinder provider config %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("subfinder provider config %q is not a regular file", path)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read subfinder provider config %q: %w", path, err)
	}

	providers := make(map[string][]string)
	if err := yaml.Unmarshal(contents, &providers); err != nil {
		return nil, fmt.Errorf("decode subfinder provider config %q: %w", path, err)
	}
	for provider, values := range providers {
		clean := make([]string, 0, len(values))
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			clean = append(clean, value)
		}
		providers[strings.ToLower(provider)] = clean
	}

	return providers, nil
}
