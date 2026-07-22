package recon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Unit-8200/recon-bot/internal/database"
	"github.com/Unit-8200/recon-bot/internal/modules/httpprobe"
)

type fakeEnumerator struct{ values []string }

func newTestStore(t *testing.T) *database.Store {
	t.Helper()
	store, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("database.Open(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedSubRun(t *testing.T, store *database.Store, domain string, startedAt time.Time, httpxOutput string) int64 {
	t.Helper()
	id, err := store.CreateRun(context.Background(), database.RunKindSubs, domain, startedAt)
	if err != nil {
		t.Fatalf("CreateRun(): %v", err)
	}
	probes := []database.HTTPProbe{}
	if httpxOutput != "" {
		for _, output := range strings.Split(strings.TrimSuffix(httpxOutput, "\n"), "\n") {
			probe := database.ProbeFromOutput(output)
			probes = append(probes, probe)
		}
	}
	if err := store.PutHTTPProbes(context.Background(), id, probes); err != nil {
		t.Fatalf("PutHTTPProbes(): %v", err)
	}
	if err := store.FinishRun(context.Background(), id, database.RunStatusCompleted, nil); err != nil {
		t.Fatalf("FinishRun(): %v", err)
	}
	return id
}

func storedSubdomains(t *testing.T, store *database.Store, runID int64) []database.Subdomain {
	t.Helper()
	values, err := store.Subdomains(context.Background(), runID)
	if err != nil {
		t.Fatalf("Subdomains(): %v", err)
	}
	return values
}

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

	store := newTestStore(t)
	service, err := New(store, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), "old\n")
	seedSubRun(t, store, "notexample.com", time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC), "other\n")
	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC), "new\n")

	result, err := service.Latest("example.com")
	if err != nil {
		t.Fatalf("Latest(): %v", err)
	}
	if result.HTTPXOutput != "new\n" {
		t.Fatalf("HTTPX output = %q", result.HTTPXOutput)
	}
	if len(result.HTTPXResults) != 1 || result.HTTPXResults[0].CLIOutput != "new" {
		t.Fatalf("HTTPX results = %#v", result.HTTPXResults)
	}
}

func TestLatestReturnsNotFound(t *testing.T) {
	t.Parallel()

	service, err := New(newTestStore(t), fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if _, err := service.Latest("example.com"); !errors.Is(err, ErrResultsNotFound) {
		t.Fatalf("Latest() error = %v, want ErrResultsNotFound", err)
	}
}

func TestResultsSupportsAllAndWildcardQueries(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	service, err := New(store, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), "one\n")
	seedSubRun(t, store, "notexample.com", time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC), "two\n")
	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC), "three\n")
	seedSubRun(t, store, "other.net", time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC), "four\n")

	all, err := service.Results("*")
	if err != nil {
		t.Fatalf("Results(*): %v", err)
	}
	if len(all) != 3 || all[0].Domain != "other.net" || all[1].Domain != "example.com" || all[2].Domain != "notexample.com" {
		t.Fatalf("Results(*) = %#v", all)
	}

	wildcard, err := service.Results("*example.com")
	if err != nil {
		t.Fatalf("Results(wildcard): %v", err)
	}
	if len(wildcard) != 2 {
		t.Fatalf("Results(wildcard) returned %d results, want 2", len(wildcard))
	}
	if wildcard[0].Domain != "example.com" || wildcard[1].Domain != "notexample.com" {
		t.Fatalf("Results(wildcard) domains = %q, %q", wildcard[0].Domain, wildcard[1].Domain)
	}

	exact, err := service.Results("example.com")
	if err != nil {
		t.Fatalf("Results(exact): %v", err)
	}
	if len(exact) != 1 || exact[0].HTTPXOutput != "three\n" {
		t.Fatalf("Results(exact) = %#v", exact)
	}
}

func TestWildcardResultsKeepNewestRunPerRootAndNewestEndpoint(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	service, err := New(store, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		"https://shared.example [200] [old example result]\nhttps://old-only.example [200]\n")
	seedSubRun(t, store, "other.net", time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC),
		"https://shared.example [301] [older shared result]\nhttps://other.example [200]\n")
	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC),
		"https://shared.example [201] [newest shared result]\nhttps://new.example [200]\n")

	results, err := service.Results("*")
	if err != nil {
		t.Fatalf("Results(*): %v", err)
	}
	if len(results) != 2 || results[0].Domain != "example.com" || results[1].Domain != "other.net" {
		t.Fatalf("wildcard results = %#v", results)
	}
	combined := CombineHTTPX(results[0].HTTPXOutput, results[1].HTTPXOutput)
	if strings.Count(combined, "https://shared.example") != 1 {
		t.Fatalf("shared endpoint was not deduplicated: %q", combined)
	}
	for _, unwanted := range []string{"old example result", "older shared result", "old-only.example"} {
		if strings.Contains(combined, unwanted) {
			t.Fatalf("combined output contains stale value %q: %q", unwanted, combined)
		}
	}
	for _, expected := range []string{"newest shared result", "https://new.example", "https://other.example"} {
		if !strings.Contains(combined, expected) {
			t.Fatalf("combined output is missing %q: %q", expected, combined)
		}
	}
	if len(results[0].HTTPXResults) != 2 || len(results[1].HTTPXResults) != 1 {
		t.Fatalf("deduplicated structured probes = %d, %d", len(results[0].HTTPXResults), len(results[1].HTTPXResults))
	}
}

func TestDomainsReturnsUniqueSortedScanHistory(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	service, err := New(store, fakeEnumerator{}, fakeValidator{}, fakeProber{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	seedSubRun(t, store, "zeta.com", time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), "")
	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC), "")
	seedSubRun(t, store, "example.com", time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC), "")

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

	service, err := New(newTestStore(t), fakeEnumerator{}, fakeValidator{}, fakeProber{})
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

	store := newTestStore(t)
	var probedTargets []string
	service, err := New(store, fakeEnumerator{values: []string{"api.example.com", "www.example.com"}}, fakeValidator{
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
	if len(probedTargets) != 1 || probedTargets[0] != "api.example.com" {
		t.Fatalf("HTTPX targets = %#v", probedTargets)
	}
	subdomains := storedSubdomains(t, store, result.RunID)
	if len(subdomains) != 2 || subdomains[0].Hostname != "api.example.com" || !subdomains[0].Resolved || subdomains[1].Hostname != "www.example.com" {
		t.Fatalf("stored subdomains = %#v", subdomains)
	}
	probes, err := store.HTTPProbes(context.Background(), result.RunID)
	if err != nil {
		t.Fatalf("HTTPProbes(): %v", err)
	}
	if len(probes) != 1 || probes[0].URL != "https://api.example.com" || probes[0].Output != "https://api.example.com [200] [API] [nginx]" {
		t.Fatalf("stored HTTP probes = %#v", probes)
	}
}

func TestRunMergesPureDNSWhenPassiveCountIsWithinThreshold(t *testing.T) {
	t.Parallel()

	var calls int
	var validatedTargets []string
	store := newTestStore(t)
	validator := recordingValidator{targets: &validatedTargets}
	service, err := New(
		store,
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
	stored := storedSubdomains(t, store, result.RunID)
	if len(stored) != 2 || !stored[0].Bruteforced || !stored[1].Bruteforced {
		t.Fatalf("stored PureDNS flags = %#v", stored)
	}
}

func TestRunSkipsPureDNSAbovePassiveThreshold(t *testing.T) {
	t.Parallel()

	var calls int
	service, err := New(
		newTestStore(t),
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
	service, err := New(newTestStore(t), blockingEnumerator{entered: entered, release: release}, fakeValidator{}, fakeProber{})
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
