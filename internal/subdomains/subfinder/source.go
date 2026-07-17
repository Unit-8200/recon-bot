// Package subfinder adapts ProjectDiscovery Subfinder as a discovery source.
package subfinder

import (
	"context"
	"fmt"
	"io"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Source wraps a Subfinder runner. Calls are serialized because the upstream
// runner maintains source statistics and rate-limit state.
type Source struct {
	runner *runner.Runner
	gate   chan struct{}
}

// New creates a Subfinder source configured to query every available source.
func New(providerConfig string) (*Source, error) {
	instance, err := runner.NewRunner(&runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
		DisableUpdateCheck: true,
		All:                true,
		ProviderConfig:     providerConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("create subfinder runner: %w", err)
	}

	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &Source{runner: instance, gate: gate}, nil
}

// Name identifies this source in logs.
func (*Source) Name() string { return "subfinder" }

// Enumerate returns Subfinder's unique candidates for domain.
func (s *Source) Enumerate(ctx context.Context, domain string) ([]string, error) {
	select {
	case <-s.gate:
		defer func() { s.gate <- struct{}{} }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	sourceMap, err := s.runner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.Discard})
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	results := make([]string, 0, len(sourceMap))
	for subdomain := range sourceMap {
		results = append(results, subdomain)
	}
	return results, nil
}
