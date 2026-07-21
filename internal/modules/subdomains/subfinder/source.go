// Package subfinder adapts ProjectDiscovery Subfinder as a discovery source.
package subfinder

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Source creates an independent Subfinder runner for each enumeration.
type Source struct {
	providerConfig string
}

// New creates a Subfinder source configured to query every available source.
func New(providerConfig string) (*Source, error) {
	return &Source{providerConfig: strings.TrimSpace(providerConfig)}, nil
}

func (s *Source) newRunner() (*runner.Runner, error) {
	instance, err := runner.NewRunner(&runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
		DisableUpdateCheck: true,
		All:                true,
		ProviderConfig:     s.providerConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("create subfinder runner: %w", err)
	}

	return instance, nil
}

// Name identifies this source in logs.
func (*Source) Name() string { return "subfinder" }

// Enumerate returns Subfinder's unique candidates for domain.
func (s *Source) Enumerate(ctx context.Context, domain string) ([]string, error) {
	instance, err := s.newRunner()
	if err != nil {
		return nil, err
	}

	sourceMap, err := instance.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.Discard})
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	results := make([]string, 0, len(sourceMap))
	for subdomain := range sourceMap {
		results = append(results, subdomain)
	}
	return results, nil
}
