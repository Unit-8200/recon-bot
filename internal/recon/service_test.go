package recon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"discord-bot/internal/httpprobe"
)

type fakeEnumerator struct{ values []string }

func (f fakeEnumerator) Enumerate(context.Context, string) ([]string, error) {
	return append([]string(nil), f.values...), nil
}

type fakeProber struct{ values []httpprobe.Result }

func (f fakeProber) Probe(context.Context, []string) ([]httpprobe.Result, error) {
	return append([]httpprobe.Result(nil), f.values...), nil
}

func TestRunPersistsArtifacts(t *testing.T) {
	t.Parallel()

	service, err := New(t.TempDir(), fakeEnumerator{values: []string{"api.example.com", "www.example.com"}}, fakeProber{
		values: []httpprobe.Result{{Input: "api.example.com", URL: "https://api.example.com", StatusCode: 200, CLIOutput: "https://api.example.com [200] [API] [nginx]"}},
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
	probes, err := os.ReadFile(result.HTTPXFile)
	if err != nil {
		t.Fatalf("read HTTPX results: %v", err)
	}
	if string(probes) != "https://api.example.com [200] [API] [nginx]\n" {
		t.Fatalf("HTTPX results = %q", probes)
	}
}
