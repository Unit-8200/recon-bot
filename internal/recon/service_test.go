package recon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"discord-bot/internal/httpprobe"
)

type fakeEnumerator struct{ values []string }

func (f fakeEnumerator) Enumerate(context.Context, string) ([]string, error) {
	return append([]string(nil), f.values...), nil
}

type fakeValidator struct{ values []string }

func (f fakeValidator) Resolve(context.Context, []string) ([]string, error) {
	return append([]string(nil), f.values...), nil
}

type fakeBruteforcer struct {
	values []string
	calls  *int
}

func (f fakeBruteforcer) Bruteforce(context.Context, string) ([]string, error) {
	if f.calls != nil {
		*f.calls++
	}
	return append([]string(nil), f.values...), nil
}

func TestLatestReturnsNewestExactDomainResult(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	service, err := New(root, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	fixtures := map[string]string{
		"20260717T120000.000Z_example.com":     HTTPXFilename,
		"20260717T130000.000Z_notexample.com":  HTTPXFilename,
		"20260717T140000.000Z_example.com":     HTTPXFilename,
		"20260717T150000.000Z_api.example.com": HTTPXFilename,
	}
	for directory, filename := range fixtures {
		path := filepath.Join(root, directory)
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatalf("Mkdir(%q): %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(path, filename), []byte("result\n"), 0o640); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}

	result, err := service.Latest("example.com")
	if err != nil {
		t.Fatalf("Latest(): %v", err)
	}
	if filepath.Base(result.Directory) != "20260717T140000.000Z_example.com" {
		t.Fatalf("directory = %q", result.Directory)
	}
	if filepath.Base(result.HTTPXFile) != HTTPXFilename {
		t.Fatalf("HTTPX file = %q", result.HTTPXFile)
	}
}

func TestLatestReturnsNotFound(t *testing.T) {
	t.Parallel()

	service, err := New(t.TempDir(), fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if _, err := service.Latest("example.com"); !errors.Is(err, ErrResultsNotFound) {
		t.Fatalf("Latest() error = %v, want ErrResultsNotFound", err)
	}
}

func TestResultsSupportsAllAndWildcardQueries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	service, err := New(root, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	directories := []string{
		"20260717T120000.000Z_example.com",
		"20260717T130000.000Z_notexample.com",
		"20260717T140000.000Z_example.com",
		"20260717T150000.000Z_other.net",
	}
	for _, directory := range directories {
		path := filepath.Join(root, directory)
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatalf("Mkdir(%q): %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(path, HTTPXFilename), []byte(directory+"\n"), 0o640); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}

	all, err := service.Results("*")
	if err != nil {
		t.Fatalf("Results(*): %v", err)
	}
	if len(all) != 4 || all[0].Domain != "other.net" || all[3].Domain != "example.com" {
		t.Fatalf("Results(*) = %#v", all)
	}

	wildcard, err := service.Results("*example.com")
	if err != nil {
		t.Fatalf("Results(wildcard): %v", err)
	}
	if len(wildcard) != 3 {
		t.Fatalf("Results(wildcard) returned %d results, want 3", len(wildcard))
	}
	if wildcard[0].Domain != "example.com" || wildcard[1].Domain != "notexample.com" || wildcard[2].Domain != "example.com" {
		t.Fatalf("Results(wildcard) domains = %q, %q, %q", wildcard[0].Domain, wildcard[1].Domain, wildcard[2].Domain)
	}

	exact, err := service.Results("example.com")
	if err != nil {
		t.Fatalf("Results(exact): %v", err)
	}
	if len(exact) != 1 || filepath.Base(exact[0].Directory) != "20260717T140000.000Z_example.com" {
		t.Fatalf("Results(exact) = %#v", exact)
	}
}

func TestDomainsReturnsUniqueSortedScanHistory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	service, err := New(root, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	for _, directory := range []string{
		"20260717T120000.000Z_zeta.com",
		"20260717T130000.000Z_example.com",
		"20260717T140000.000Z_example.com_1",
		"not-a-scan-directory",
	} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o750); err != nil {
			t.Fatalf("Mkdir(%q): %v", directory, err)
		}
	}

	got, err := service.Domains()
	if err != nil {
		t.Fatalf("Domains(): %v", err)
	}
	want := []string{"example.com", "zeta.com"}
	if !equalStrings(got, want) {
		t.Fatalf("Domains() = %#v, want %#v", got, want)
	}
}

func TestDomainsReturnsNotFoundForEmptyHistory(t *testing.T) {
	t.Parallel()

	service, err := New(t.TempDir(), fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if _, err := service.Domains(); !errors.Is(err, ErrResultsNotFound) {
		t.Fatalf("Domains() error = %v, want ErrResultsNotFound", err)
	}
}

type fakeProber struct {
	values  []httpprobe.Result
	targets *[]string
}

func (f fakeProber) Probe(_ context.Context, targets []string) ([]httpprobe.Result, error) {
	if f.targets != nil {
		*f.targets = append([]string(nil), targets...)
	}
	return append([]httpprobe.Result(nil), f.values...), nil
}

func TestRunPersistsArtifacts(t *testing.T) {
	t.Parallel()

	var probedTargets []string
	service, err := New(t.TempDir(), fakeEnumerator{values: []string{"api.example.com", "www.example.com"}}, fakeValidator{
		values: []string{"api.example.com"},
	}, fakeProber{
		values:  []httpprobe.Result{{Input: "api.example.com", URL: "https://api.example.com", StatusCode: 200, CLIOutput: "https://api.example.com [200] [API] [nginx]"}},
		targets: &probedTargets,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	service.now = func() time.Time { return time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC) }

	result, err := service.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run(): %v", err)
	}
	if filepath.Base(result.Directory) != "20260717T120000.000Z_example.com" {
		t.Fatalf("directory = %q", result.Directory)
	}

	raw, err := os.ReadFile(result.SubdomainsFile)
	if err != nil {
		t.Fatalf("read subdomains: %v", err)
	}
	if string(raw) != "api.example.com\nwww.example.com\n" {
		t.Fatalf("subdomains file = %q", raw)
	}
	resolved, err := os.ReadFile(result.ResolvedFile)
	if err != nil {
		t.Fatalf("read resolved subdomains: %v", err)
	}
	if string(resolved) != "api.example.com\n" {
		t.Fatalf("resolved subdomains file = %q", resolved)
	}
	if len(probedTargets) != 1 || probedTargets[0] != "api.example.com" {
		t.Fatalf("HTTPX targets = %#v", probedTargets)
	}
	probes, err := os.ReadFile(result.HTTPXFile)
	if err != nil {
		t.Fatalf("read HTTPX results: %v", err)
	}
	if string(probes) != "https://api.example.com [200] [API] [nginx]\n" {
		t.Fatalf("HTTPX results = %q", probes)
	}
}

func TestRunMergesPureDNSWhenPassiveCountIsWithinThreshold(t *testing.T) {
	t.Parallel()

	var calls int
	var validatedTargets []string
	validator := recordingValidator{targets: &validatedTargets}
	service, err := New(
		t.TempDir(),
		fakeEnumerator{values: []string{"www.example.com"}},
		validator,
		fakeProber{},
		WithBruteforcer(fakeBruteforcer{
			values: []string{"API.EXAMPLE.COM.", "www.example.com", "outside.test", "not a domain"},
			calls:  &calls,
		}, 1),
	)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	result, err := service.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run(): %v", err)
	}
	if calls != 1 {
		t.Fatalf("PureDNS calls = %d, want 1", calls)
	}
	want := []string{"api.example.com", "www.example.com"}
	if !equalStrings(result.Subdomains, want) {
		t.Fatalf("subdomains = %#v, want %#v", result.Subdomains, want)
	}
	if !equalStrings(validatedTargets, want) {
		t.Fatalf("validated targets = %#v, want %#v", validatedTargets, want)
	}
	pureDNSContents, err := os.ReadFile(result.PureDNSFile)
	if err != nil {
		t.Fatalf("read PureDNS artifact: %v", err)
	}
	if string(pureDNSContents) != "api.example.com\nwww.example.com\n" {
		t.Fatalf("PureDNS artifact = %q", pureDNSContents)
	}
}

func TestRunSkipsPureDNSAbovePassiveThreshold(t *testing.T) {
	t.Parallel()

	var calls int
	service, err := New(
		t.TempDir(),
		fakeEnumerator{values: []string{"a.example.com", "b.example.com"}},
		fakeValidator{},
		fakeProber{},
		WithBruteforcer(fakeBruteforcer{calls: &calls}, 1),
	)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if _, err := service.Run(context.Background(), "example.com"); err != nil {
		t.Fatalf("Run(): %v", err)
	}
	if calls != 0 {
		t.Fatalf("PureDNS calls = %d, want 0", calls)
	}
}

type recordingValidator struct{ targets *[]string }

func (r recordingValidator) Resolve(_ context.Context, targets []string) ([]string, error) {
	*r.targets = append([]string(nil), targets...)
	return append([]string(nil), targets...), nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type blockingEnumerator struct {
	entered chan struct{}
	release chan struct{}
}

func (b blockingEnumerator) Enumerate(ctx context.Context, _ string) ([]string, error) {
	select {
	case b.entered <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-b.release:
		return []string{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestRunAllowsTwoConcurrentScans(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	service, err := New(t.TempDir(), blockingEnumerator{entered: entered, release: release}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	errorsChannel := make(chan error, 3)
	var scans sync.WaitGroup
	for _, domain := range []string{"example.com", "example.net", "example.org"} {
		scans.Add(1)
		go func() {
			defer scans.Done()
			_, runErr := service.Run(context.Background(), domain)
			errorsChannel <- runErr
		}()
	}

	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("two scans did not start concurrently")
		}
	}
	select {
	case <-entered:
		t.Fatal("third scan started before a slot was released")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	scans.Wait()
	close(errorsChannel)
	for runErr := range errorsChannel {
		if runErr != nil {
			t.Fatalf("Run(): %v", runErr)
		}
	}
}
