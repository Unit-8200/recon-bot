// Package subdomains consolidates passive discovery results from independent sources.
package subdomains

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	githubsubs "discord-bot/internal/modules/subdomains/github-subs"
	"discord-bot/internal/modules/subdomains/shosubgo"
	subfindersource "discord-bot/internal/modules/subdomains/subfinder"
)

type source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// FinderOptions configures credentials shared by the discovery sources.
type FinderOptions struct {
	// ProviderConfig points to Subfinder's provider-config.yaml. The consolidated
	// finder also reuses its github and shodan entries for those adapters.
	ProviderConfig string
}

// Finder runs passive sources and consolidates their results.
type Finder struct {
	sources []source
}

// NewFinder creates a finder using all Subfinder sources and its default provider config.
func NewFinder() (*Finder, error) {
	return NewFinderWithOptions(FinderOptions{})
}

// NewFinderWithOptions creates all sources for which credentials are available.
func NewFinderWithOptions(options FinderOptions) (*Finder, error) {
	providers, err := loadProviderConfig(options.ProviderConfig)
	if err != nil {
		return nil, err
	}

	subfinderSource, err := subfindersource.New(strings.TrimSpace(options.ProviderConfig))
	if err != nil {
		return nil, err
	}

	sources := []source{subfinderSource}
	if keys := providers["shodan"]; len(keys) > 0 {
		sources = append(sources, shosubgo.New(keys[0]))
	}
	if tokens := providers["github"]; len(tokens) > 0 {
		sources = append(sources, githubsubs.New(tokens))
	}

	return &Finder{sources: sources}, nil
}

type sourceResult struct {
	name       string
	candidates []string
	err        error
}

// Enumerate runs every configured passive source concurrently and returns one
// unique, sorted result set. A failing source does not discard successful data.
func (f *Finder) Enumerate(ctx context.Context, rootDomain string) ([]string, error) {
	if f == nil || len(f.sources) == 0 {
		return nil, fmt.Errorf("subdomain finder has no sources")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	domain, err := NormalizeRootDomain(rootDomain)
	if err != nil {
		return nil, err
	}

	results := make(chan sourceResult, len(f.sources))
	var waitGroup sync.WaitGroup
	for _, currentSource := range f.sources {
		waitGroup.Add(1)
		go func(currentSource source) {
			defer waitGroup.Done()
			candidates, sourceErr := currentSource.Enumerate(ctx, domain)
			results <- sourceResult{name: currentSource.Name(), candidates: candidates, err: sourceErr}
		}(currentSource)
	}
	go func() {
		waitGroup.Wait()
		close(results)
	}()

	unique := make(map[string]struct{})
	var sourceErrors []error
	successfulSources := 0
	for result := range results {
		if result.err != nil {
			wrapped := fmt.Errorf("%s: %w", result.name, result.err)
			sourceErrors = append(sourceErrors, wrapped)
			log.Printf("subdomain source failed: %v", wrapped)
			continue
		}
		successfulSources++
		for _, candidate := range result.candidates {
			if normalized, ok := NormalizeCandidate(candidate, domain); ok {
				unique[normalized] = struct{}{}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if successfulSources == 0 {
		return nil, fmt.Errorf("all subdomain sources failed: %w", errors.Join(sourceErrors...))
	}

	consolidated := make([]string, 0, len(unique))
	for candidate := range unique {
		consolidated = append(consolidated, candidate)
	}
	sort.Strings(consolidated)
	return consolidated, nil
}
