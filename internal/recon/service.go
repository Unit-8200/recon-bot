// Package recon orchestrates passive enumeration, HTTP probing, and artifacts.
package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"discord-bot/internal/httpprobe"
	"discord-bot/internal/subdomains"
)

const (
	SubdomainsFilename = "raw_subdomains.txt"
	HTTPXFilename      = "httpx_results.txt"
)

// Enumerator provides the passive discovery phase.
type Enumerator interface {
	Enumerate(ctx context.Context, rootDomain string) ([]string, error)
}

// Prober provides the HTTP enrichment phase.
type Prober interface {
	Probe(ctx context.Context, targets []string) ([]httpprobe.Result, error)
}

// Result describes one persisted reconnaissance run.
type Result struct {
	Domain         string
	Directory      string
	Subdomains     []string
	HTTPXResults   []httpprobe.Result
	SubdomainsFile string
	HTTPXFile      string
}

// Service runs and persists the two-stage workflow.
type Service struct {
	outputRoot string
	enumerator Enumerator
	prober     Prober
	now        func() time.Time
}

// New creates a reconnaissance workflow.
func New(outputRoot string, enumerator Enumerator, prober Prober) (*Service, error) {
	outputRoot = strings.TrimSpace(outputRoot)
	if outputRoot == "" {
		return nil, fmt.Errorf("results directory is required")
	}
	if enumerator == nil {
		return nil, fmt.Errorf("subdomain enumerator is required")
	}
	if prober == nil {
		return nil, fmt.Errorf("HTTP prober is required")
	}
	return &Service{outputRoot: outputRoot, enumerator: enumerator, prober: prober, now: time.Now}, nil
}

// Run enumerates a root domain, saves the raw list, probes it, and saves HTTPX's plain output.
func (s *Service) Run(ctx context.Context, rootDomain string) (Result, error) {
	domain, err := subdomains.NormalizeRootDomain(rootDomain)
	if err != nil {
		return Result{}, err
	}

	discovered, err := s.enumerator.Enumerate(ctx, domain)
	if err != nil {
		return Result{}, fmt.Errorf("enumerate subdomains: %w", err)
	}

	directory, err := s.createRunDirectory(domain)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Domain:         domain,
		Directory:      directory,
		Subdomains:     discovered,
		SubdomainsFile: filepath.Join(directory, SubdomainsFilename),
		HTTPXFile:      filepath.Join(directory, HTTPXFilename),
	}

	if err := writeLines(result.SubdomainsFile, discovered); err != nil {
		return result, fmt.Errorf("write raw subdomains: %w", err)
	}

	probes, probeErr := s.prober.Probe(ctx, discovered)
	result.HTTPXResults = probes
	if err := writeHTTPXLines(result.HTTPXFile, probes); err != nil {
		return result, fmt.Errorf("write HTTPX results: %w", err)
	}
	if probeErr != nil {
		return result, fmt.Errorf("probe discovered subdomains: %w", probeErr)
	}

	return result, nil
}

func (s *Service) createRunDirectory(domain string) (string, error) {
	if err := os.MkdirAll(s.outputRoot, 0o750); err != nil {
		return "", fmt.Errorf("create results root: %w", err)
	}

	baseName := s.now().UTC().Format("20060102T150405.000Z") + "_" + domain
	for suffix := 0; ; suffix++ {
		name := baseName
		if suffix > 0 {
			name = fmt.Sprintf("%s_%d", baseName, suffix)
		}
		directory := filepath.Join(s.outputRoot, name)
		err := os.Mkdir(directory, 0o750)
		if err == nil {
			return directory, nil
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("create run directory: %w", err)
		}
	}
}

func writeLines(path string, values []string) error {
	contents := ""
	if len(values) > 0 {
		contents = strings.Join(values, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(contents), 0o640)
}

func writeHTTPXLines(path string, results []httpprobe.Result) error {
	sort.Slice(results, func(left, right int) bool {
		if results[left].URL == results[right].URL {
			return results[left].Input < results[right].Input
		}
		return results[left].URL < results[right].URL
	})

	lines := make([]string, 0, len(results))
	for _, result := range results {
		if result.CLIOutput != "" {
			lines = append(lines, result.CLIOutput)
		}
	}
	return writeLines(path, lines)
}
