// Package recon orchestrates passive enumeration, HTTP probing, and persistence.
package recon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path"
	"sort"
	"strings"
	"time"

	"discord-bot/internal/database"
	"discord-bot/internal/modules/httpprobe"
	"discord-bot/internal/modules/subdomains"
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
	RunID        int64
	Domain       string
	StartedAt    time.Time
	Subdomains   []string
	Passive      []string
	PureDNS      []string
	Resolved     []string
	HTTPXResults []httpprobe.Result
	HTTPXOutput  string
}

// Service runs and persists the discovery, DNS-validation, and HTTP-probing workflow.
type Service struct {
	store          *database.Store
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
func New(store *database.Store, enumerator Enumerator, validator DNSValidator, prober Prober, options ...Option) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("database store is required")
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
		store:      store,
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
func (s *Service) Run(ctx context.Context, rootDomain string) (result Result, runErr error) {
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
	result = Result{Domain: domain, StartedAt: s.now().UTC()}
	result.RunID, err = s.store.CreateRun(ctx, database.RunKindSubs, domain, result.StartedAt)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		status := database.RunStatusCompleted
		if runErr != nil {
			status = database.RunStatusFailed
		}
		if finishErr := s.store.FinishRun(context.Background(), result.RunID, status, runErr); finishErr != nil && runErr == nil {
			runErr = finishErr
		}
	}()

	passive, err := s.enumerator.Enumerate(ctx, domain)
	if err != nil {
		return result, fmt.Errorf("enumerate subdomains: %w", err)
	}
	result.Passive = passive
	if err := s.store.PutSubdomains(ctx, result.RunID, passive, database.SubdomainStagePassive); err != nil {
		return result, fmt.Errorf("save passive subdomains: %w", err)
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
	if err := s.store.PutSubdomains(ctx, result.RunID, result.PureDNS, database.SubdomainStageBruteforced); err != nil {
		return result, fmt.Errorf("save PureDNS subdomains: %w", err)
	}

	result.Subdomains = mergeDomains(passive, result.PureDNS)
	if err := s.store.PutSubdomains(ctx, result.RunID, result.Subdomains, database.SubdomainStageDiscovered); err != nil {
		return result, fmt.Errorf("save raw subdomains: %w", err)
	}

	resolved, resolveErr := s.validator.Resolve(ctx, result.Subdomains)
	result.Resolved = resolved
	if err := s.store.PutSubdomains(ctx, result.RunID, resolved, database.SubdomainStageResolved); err != nil {
		return result, fmt.Errorf("save resolved subdomains: %w", err)
	}
	if resolveErr != nil {
		return result, fmt.Errorf("validate subdomain DNS: %w", resolveErr)
	}
	log.Printf("DNS validation for %s: %d/%d subdomains resolved", domain, len(resolved), len(result.Subdomains))

	probes, probeErr := s.prober.Probe(ctx, resolved)
	result.HTTPXResults = probes
	result.HTTPXOutput = httpxLines(probes)
	if err := s.store.PutHTTPProbes(ctx, result.RunID, databaseProbes(probes)); err != nil {
		return result, fmt.Errorf("save HTTPX results: %w", err)
	}
	if probeErr != nil {
		return result, fmt.Errorf("probe discovered subdomains: %w", probeErr)
	}

	return result, nil
}

// Latest returns the newest persisted HTTPX results for an exact root domain.
func (s *Service) Latest(rootDomain string) (Result, error) {
	results, err := s.Results(rootDomain)
	if err != nil {
		return Result{}, err
	}
	return results[0], nil
}

// Results returns completed HTTPX results matching a query. Exact domains
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

	runs, err := s.store.CompletedSubRuns(context.Background())
	if err != nil {
		return nil, fmt.Errorf("read scan results: %w", err)
	}

	results := make([]Result, 0)
	for _, run := range runs {
		matched := !wildcard && run.Domain == query
		if wildcard {
			matched, _ = path.Match(query, run.Domain)
		}
		if !matched {
			continue
		}
		probes, probeErr := s.store.HTTPProbes(context.Background(), run.ID)
		if probeErr != nil {
			return nil, fmt.Errorf("read HTTP probes for run %d: %w", run.ID, probeErr)
		}
		results = append(results, Result{
			RunID:        run.ID,
			Domain:       run.Domain,
			StartedAt:    run.StartedAt,
			HTTPXResults: httpxResultsFromDatabase(probes),
			HTTPXOutput:  databaseHTTPXLines(probes),
		})
		if !wildcard {
			break
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("%w for %s", ErrResultsNotFound, query)
	}
	return results, nil
}

// Domains returns every unique root domain represented in the saved scan history.
func (s *Service) Domains() ([]string, error) {
	domains, err := s.store.Domains(context.Background(), database.RunKindSubs)
	if err != nil {
		return nil, fmt.Errorf("read scan history: %w", err)
	}
	if len(domains) == 0 {
		return nil, ErrResultsNotFound
	}
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

func lines(values []string) string {
	contents := ""
	if len(values) > 0 {
		contents = strings.Join(values, "\n") + "\n"
	}
	return contents
}

func httpxLines(results []httpprobe.Result) string {
	sort.Slice(results, func(left, right int) bool {
		if results[left].URL == results[right].URL {
			return results[left].Input < results[right].Input
		}
		return results[left].URL < results[right].URL
	})

	outputLines := make([]string, 0, len(results))
	for _, result := range results {
		if result.CLIOutput != "" {
			outputLines = append(outputLines, result.CLIOutput)
		}
	}
	return lines(outputLines)
}

func databaseProbes(results []httpprobe.Result) []database.HTTPProbe {
	probes := make([]database.HTTPProbe, 0, len(results))
	for _, result := range results {
		probes = append(probes, database.HTTPProbe{
			Timestamp:     result.Timestamp,
			Input:         result.Input,
			URL:           result.URL,
			FinalURL:      result.FinalURL,
			Scheme:        result.Scheme,
			Host:          result.Host,
			Port:          result.Port,
			StatusCode:    result.StatusCode,
			Title:         result.Title,
			Technologies:  append([]string(nil), result.Technologies...),
			WebServer:     result.WebServer,
			IPs:           append([]string(nil), result.IPs...),
			CDN:           result.CDN,
			CDNName:       result.CDNName,
			CDNType:       result.CDNType,
			ContentLength: result.ContentLength,
			ContentType:   result.ContentType,
			BodyPreview:   result.BodyPreview,
			Location:      result.Location,
			Error:         result.Error,
			Output:        result.CLIOutput,
		})
	}
	return probes
}

func databaseHTTPXLines(probes []database.HTTPProbe) string {
	values := make([]string, 0, len(probes))
	for _, probe := range probes {
		if probe.Output != "" {
			values = append(values, probe.Output)
		}
	}
	return lines(values)
}

func httpxResultsFromDatabase(probes []database.HTTPProbe) []httpprobe.Result {
	results := make([]httpprobe.Result, 0, len(probes))
	for _, probe := range probes {
		results = append(results, httpprobe.Result{
			CLIOutput:     probe.Output,
			Timestamp:     probe.Timestamp,
			Input:         probe.Input,
			URL:           probe.URL,
			FinalURL:      probe.FinalURL,
			Scheme:        probe.Scheme,
			Host:          probe.Host,
			Port:          probe.Port,
			StatusCode:    probe.StatusCode,
			Title:         probe.Title,
			Technologies:  append([]string(nil), probe.Technologies...),
			WebServer:     probe.WebServer,
			IPs:           append([]string(nil), probe.IPs...),
			CDN:           probe.CDN,
			CDNName:       probe.CDNName,
			CDNType:       probe.CDNType,
			ContentLength: probe.ContentLength,
			ContentType:   probe.ContentType,
			BodyPreview:   probe.BodyPreview,
			Location:      probe.Location,
			Error:         probe.Error,
		})
	}
	return results
}
