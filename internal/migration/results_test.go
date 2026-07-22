package migration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Unit-8200/recon-bot/internal/database"
	"github.com/Unit-8200/recon-bot/internal/modules/ipscan"
	"github.com/Unit-8200/recon-bot/internal/recon"
)

func TestResultsImportsLegacyRunsIdempotently(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeLegacyArtifact(t, root, "20260720T120000.000Z_example.com", recon.PassiveFilename, "www.example.com\n")
	writeLegacyArtifact(t, root, "20260720T120000.000Z_example.com", recon.HTTPXFilename, "https://www.example.com [200]\n")
	writeLegacyArtifact(t, root, "20260720T130000.000Z_ips", ipscan.TargetsFilename, "192.0.2.1\n")
	writeLegacyArtifact(t, root, "20260720T130000.000Z_ips", ipscan.ResultsFilename, "cert.example\n")
	if err := os.Mkdir(filepath.Join(root, "not-a-run"), 0o750); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}

	store, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("database.Open(): %v", err)
	}
	defer store.Close()

	report, err := Results(context.Background(), store, root)
	if err != nil {
		t.Fatalf("Results(): %v", err)
	}
	if report.Imported != 2 || report.Skipped != 0 || report.Ignored != 1 {
		t.Fatalf("first report = %#v", report)
	}
	report, err = Results(context.Background(), store, root)
	if err != nil {
		t.Fatalf("second Results(): %v", err)
	}
	if report.Imported != 0 || report.Skipped != 2 || report.Ignored != 1 {
		t.Fatalf("second report = %#v", report)
	}

	subs, err := store.Runs(context.Background(), database.RunKindSubs)
	if err != nil || len(subs) != 1 || subs[0].Domain != "example.com" {
		t.Fatalf("sub runs = %#v, %v", subs, err)
	}
	probes, err := store.HTTPProbes(context.Background(), subs[0].ID)
	if err != nil || len(probes) != 1 || probes[0].URL != "https://www.example.com" {
		t.Fatalf("HTTP probes = %#v, %v", probes, err)
	}
	ips, err := store.Runs(context.Background(), database.RunKindIPs)
	if err != nil || len(ips) != 1 {
		t.Fatalf("IP runs = %#v, %v", ips, err)
	}
	domains, err := store.IPDomains(context.Background(), ips[0].ID)
	if err != nil || len(domains) != 1 || domains[0] != "cert.example" {
		t.Fatalf("IP domains = %#v, %v", domains, err)
	}
}

func writeLegacyArtifact(t *testing.T, root, directory, name, contents string) {
	t.Helper()
	path := filepath.Join(root, directory)
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("MkdirAll(): %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, name), []byte(contents), 0o640); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
}
