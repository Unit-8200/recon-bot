// Package recon orchestrates passive enumeration, HTTP probing, and artifacts.
package recon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"discord-bot/internal/httpprobe"
	"discord-bot/internal/subdomains"
)

const (
	SubdomainsFilename = "raw_subdomains.txt"
	PassiveFilename    = "passive_subdomains.txt"
	PureDNSFilename    = "puredns_subdomains.txt"
	ResolvedFilename   = "resolved_subdomains.txt"
	HTTPXFilename      = "httpx_results.txt"
	DomainsFilename    = "domains.txt"
	maxConcurrentScans = 2
)

// ErrResultsNotFound indicates that no completed scan exists for a domain.
var ErrResultsNotFound = errors.New("scan results not found")

// Enumerator provides the passive discovery phase.
type Enumerator interface {
	Enumerate(ctx context.Context, rootDomain string) ([]string, error)
}

// DNSValidator provides the live-DNS filtering phase.
type DNSValidator interface {
	Resolve(ctx context.Context, targets []string) ([]string, error)
}

// Bruteforcer provides the optional active DNS discovery phase.
type Bruteforcer interface {
	Bruteforce(ctx context.Context, rootDomain string) ([]string, error)
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
	Passive        []string
	PureDNS        []string
	Resolved       []string
	HTTPXResults   []httpprobe.Result
	SubdomainsFile string
	PassiveFile    string
	PureDNSFile    string
	ResolvedFile   string
	HTTPXFile      string
}

// Service runs and persists the discovery, DNS-validation, and HTTP-probing workflow.
type Service struct {
	outputRoot     string
	enumerator     Enumerator
	validator      DNSValidator
	prober         Prober
	bruteforcer    Bruteforcer
	bruteThreshold int
	now            func() time.Time
	scanGate       chan struct{}
}

// Option customizes a reconnaissance workflow.
type Option func(*Service) error

// WithBruteforcer enables active DNS discovery when passive results do not
// exceed passiveThreshold. A threshold of zero runs only when passive discovery
// found no names.
func WithBruteforcer(bruteforcer Bruteforcer, passiveThreshold int) Option {
	return func(service *Service) error {
		if bruteforcer == nil {
			return fmt.Errorf("DNS bruteforcer is required")
		}
		if passiveThreshold < 0 {
			return fmt.Errorf("PureDNS passive threshold cannot be negative")
		}
		service.bruteforcer = bruteforcer
		service.bruteThreshold = passiveThreshold
		return nil
	}
}

// New creates a reconnaissance workflow.
func New(outputRoot string, enumerator Enumerator, validator DNSValidator, prober Prober, options ...Option) (*Service, error) {
	outputRoot = strings.TrimSpace(outputRoot)
	if outputRoot == "" {
		return nil, fmt.Errorf("results directory is required")
	}
	if enumerator == nil {
		return nil, fmt.Errorf("subdomain enumerator is required")
	}
	if validator == nil {
		return nil, fmt.Errorf("DNS validator is required")
	}
	if prober == nil {
		return nil, fmt.Errorf("HTTP prober is required")
	}
	service := &Service{
		outputRoot: outputRoot,
		enumerator: enumerator,
		validator:  validator,
		prober:     prober,
		now:        time.Now,
		scanGate:   make(chan struct{}, maxConcurrentScans),
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("recon option is required")
		}
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// Run enumerates a root domain, validates DNS, probes live names, and saves each artifact.
func (s *Service) Run(ctx context.Context, rootDomain string) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("context is required")
	}
	domain, err := subdomains.NormalizeRootDomain(rootDomain)
	if err != nil {
		return Result{}, err
	}
	select {
	case s.scanGate <- struct{}{}:
		defer func() { <-s.scanGate }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}

	passive, err := s.enumerator.Enumerate(ctx, domain)
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
		Passive:        passive,
		SubdomainsFile: filepath.Join(directory, SubdomainsFilename),
		PassiveFile:    filepath.Join(directory, PassiveFilename),
		PureDNSFile:    filepath.Join(directory, PureDNSFilename),
		ResolvedFile:   filepath.Join(directory, ResolvedFilename),
		HTTPXFile:      filepath.Join(directory, HTTPXFilename),
	}

	if err := writeLines(result.PassiveFile, passive); err != nil {
		return result, fmt.Errorf("write passive subdomains: %w", err)
	}

	if s.bruteforcer != nil && len(passive) <= s.bruteThreshold {
		log.Printf("Passive discovery for %s returned %d names; starting PureDNS brute force", domain, len(passive))
		brute, bruteErr := s.bruteforcer.Bruteforce(ctx, domain)
		if bruteErr != nil {
			if ctx.Err() != nil {
				return result, fmt.Errorf("brute-force subdomains: %w", bruteErr)
			}
			log.Printf("PureDNS brute force for %s failed; continuing with passive results: %v", domain, bruteErr)
		} else {
			result.PureDNS = scopedDomains(brute, domain)
			log.Printf("PureDNS brute force for %s found %d scoped names", domain, len(result.PureDNS))
		}
	}
	if err := writeLines(result.PureDNSFile, result.PureDNS); err != nil {
		return result, fmt.Errorf("write PureDNS subdomains: %w", err)
	}

	result.Subdomains = mergeDomains(passive, result.PureDNS)
	if err := writeLines(result.SubdomainsFile, result.Subdomains); err != nil {
		return result, fmt.Errorf("write raw subdomains: %w", err)
	}

	resolved, resolveErr := s.validator.Resolve(ctx, result.Subdomains)
	result.Resolved = resolved
	if err := writeLines(result.ResolvedFile, resolved); err != nil {
		return result, fmt.Errorf("write resolved subdomains: %w", err)
	}
	if resolveErr != nil {
		return result, fmt.Errorf("validate subdomain DNS: %w", resolveErr)
	}
	log.Printf("DNS validation for %s: %d/%d subdomains resolved", domain, len(resolved), len(result.Subdomains))

	probes, probeErr := s.prober.Probe(ctx, resolved)
	result.HTTPXResults = probes
	if err := writeHTTPXLines(result.HTTPXFile, probes); err != nil {
		return result, fmt.Errorf("write HTTPX results: %w", err)
	}
	if probeErr != nil {
		return result, fmt.Errorf("probe discovered subdomains: %w", probeErr)
	}

	return result, nil
}

// Latest returns the newest persisted HTTPX artifact for an exact root domain.
func (s *Service) Latest(rootDomain string) (Result, error) {
	results, err := s.Results(rootDomain)
	if err != nil {
		return Result{}, err
	}
	return results[0], nil
}

// Results returns completed HTTPX artifacts matching a query. Exact domains
// return only their newest run; queries containing * return every matching run,
// ordered newest first. A query containing only * matches every completed run.
func (s *Service) Results(query string) ([]Result, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	wildcard := strings.Contains(query, "*")
	if query == "" {
		return nil, fmt.Errorf("results query is required")
	}
	if !wildcard {
		domain, err := subdomains.NormalizeRootDomain(query)
		if err != nil {
			return nil, err
		}
		query = domain
	} else if wildcard {
		for _, character := range query {
			if character == '*' || character == '.' || character == '-' ||
				(character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
				continue
			}
			return nil, fmt.Errorf("results wildcard may contain only domain text and *")
		}
		if _, err := path.Match(query, "example.com"); err != nil {
			return nil, fmt.Errorf("invalid results wildcard: %w", err)
		}
	}

	entries, err := os.ReadDir(s.outputRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w for %s", ErrResultsNotFound, query)
	}
	if err != nil {
		return nil, fmt.Errorf("read results directory: %w", err)
	}

	candidates := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domain, ok := runDirectoryDomain(entry.Name())
		if !ok {
			continue
		}
		matched := !wildcard && domain == query
		if wildcard {
			matched, _ = path.Match(query, domain)
		}
		if matched {
			candidates = append(candidates, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(candidates)))

	results := make([]Result, 0, len(candidates))
	for _, name := range candidates {
		directory := filepath.Join(s.outputRoot, name)
		httpxPath := filepath.Join(directory, HTTPXFilename)
		if info, statErr := os.Stat(httpxPath); statErr == nil && info.Mode().IsRegular() {
			domain, _ := runDirectoryDomain(name)
			results = append(results, Result{
				Domain:         domain,
				Directory:      directory,
				SubdomainsFile: filepath.Join(directory, SubdomainsFilename),
				PassiveFile:    filepath.Join(directory, PassiveFilename),
				PureDNSFile:    filepath.Join(directory, PureDNSFilename),
				ResolvedFile:   filepath.Join(directory, ResolvedFilename),
				HTTPXFile:      httpxPath,
			})
			if !wildcard {
				break
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("%w for %s", ErrResultsNotFound, query)
	}
	return results, nil
}

// Domains returns every unique root domain represented in the saved scan history.
func (s *Service) Domains() ([]string, error) {
	entries, err := os.ReadDir(s.outputRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrResultsNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read results directory: %w", err)
	}

	unique := make(map[string]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if domain, ok := runDirectoryDomain(entry.Name()); ok {
			unique[domain] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil, ErrResultsNotFound
	}

	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains, nil
}

func scopedDomains(values []string, rootDomain string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if domain, ok := subdomains.NormalizeCandidate(value, rootDomain); ok {
			result = append(result, domain)
		}
	}
	return mergeDomains(result)
}

func mergeDomains(groups ...[]string) []string {
	seen := make(map[string]struct{})
	merged := make([]string, 0)
	for _, group := range groups {
		for _, value := range group {
			value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
			if value == "" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			merged = append(merged, value)
		}
	}
	sort.Strings(merged)
	return merged
}

func runDirectoryMatches(name, domain string) bool {
	parsedDomain, ok := runDirectoryDomain(name)
	return ok && parsedDomain == domain
}

func runDirectoryDomain(name string) (string, bool) {
	const timestampLength = len("20060102T150405.000Z")
	if len(name) <= timestampLength || name[timestampLength] != '_' {
		return "", false
	}
	if _, err := time.Parse("20060102T150405.000Z", name[:timestampLength]); err != nil {
		return "", false
	}

	remainder := name[timestampLength+1:]
	if separator := strings.LastIndexByte(remainder, '_'); separator >= 0 {
		if _, err := strconv.ParseUint(remainder[separator+1:], 10, 32); err == nil {
			remainder = remainder[:separator]
		}
	}
	domain, err := subdomains.NormalizeRootDomain(remainder)
	return domain, err == nil
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
