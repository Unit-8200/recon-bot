package migration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Unit-8200/recon-bot/internal/database"
	"github.com/Unit-8200/recon-bot/internal/recon"
)

func TestDatabaseMergeAfterFolderIsAdditiveAndIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	legacyFolder := t.TempDir()
	writeLegacyArtifact(t, legacyFolder, "20260720T120000.000Z_folder.example", recon.PassiveFilename, "www.folder.example\n")
	writeLegacyArtifact(t, legacyFolder, "20260720T120000.000Z_folder.example", recon.HTTPXFilename, "https://www.folder.example [200]\n")

	sourcePath := filepath.Join(t.TempDir(), "previous.db")
	source, err := database.Open(sourcePath)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	if _, err := Results(ctx, source, legacyFolder); err != nil {
		t.Fatalf("seed source legacy run: %v", err)
	}
	startedAt := time.Date(2026, 7, 21, 10, 30, 0, 0, time.UTC)
	subRunID, err := source.CreateRun(ctx, database.RunKindSubs, "database.example", startedAt)
	if err != nil {
		t.Fatalf("create source sub run: %v", err)
	}
	if err := source.PutSubdomains(ctx, subRunID, []string{"www.database.example"}, database.SubdomainStageResolved); err != nil {
		t.Fatalf("seed source subdomains: %v", err)
	}
	if err := source.PutHTTPProbes(ctx, subRunID, []database.HTTPProbe{{URL: "https://www.database.example", StatusCode: 200}}); err != nil {
		t.Fatalf("seed source probes: %v", err)
	}
	if err := source.FinishRun(ctx, subRunID, database.RunStatusCompleted, nil); err != nil {
		t.Fatalf("finish source sub run: %v", err)
	}
	ipRunID, err := source.CreateRun(ctx, database.RunKindIPs, "", startedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("create source IP run: %v", err)
	}
	if err := source.PutIPTargets(ctx, ipRunID, []string{"192.0.2.0/24"}); err != nil {
		t.Fatalf("seed source IP targets: %v", err)
	}
	if err := source.PutIPDomains(ctx, ipRunID, []string{"cert.database.example"}); err != nil {
		t.Fatalf("seed source IP domains: %v", err)
	}
	if err := source.FinishRun(ctx, ipRunID, database.RunStatusCompleted, nil); err != nil {
		t.Fatalf("finish source IP run: %v", err)
	}
	if _, err := source.AddStoredItem(ctx, "source-only", "from old database"); err != nil {
		t.Fatalf("seed source item: %v", err)
	}
	if _, err := source.AddStoredItem(ctx, "shared", "source description"); err != nil {
		t.Fatalf("seed shared source item: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}

	destination, err := database.Open(filepath.Join(t.TempDir(), "current.db"))
	if err != nil {
		t.Fatalf("open destination: %v", err)
	}
	defer destination.Close()
	if _, err := Results(ctx, destination, legacyFolder); err != nil {
		t.Fatalf("import folder first: %v", err)
	}
	if _, err := destination.AddStoredItem(ctx, "shared", ""); err != nil {
		t.Fatalf("seed destination item: %v", err)
	}

	report, err := Database(ctx, destination, sourcePath)
	if err != nil {
		t.Fatalf("Database(): %v", err)
	}
	if report.Imported != 2 || report.Skipped != 1 || report.ItemsImported != 1 || report.ItemsSkipped != 1 {
		t.Fatalf("first database report = %#v", report)
	}
	report, err = Database(ctx, destination, sourcePath)
	if err != nil {
		t.Fatalf("second Database(): %v", err)
	}
	if report.Imported != 0 || report.Skipped != 3 || report.ItemsImported != 0 || report.ItemsSkipped != 2 {
		t.Fatalf("second database report = %#v", report)
	}

	subRuns, err := destination.Runs(ctx, database.RunKindSubs)
	if err != nil || len(subRuns) != 2 {
		t.Fatalf("merged sub runs = %#v, %v", subRuns, err)
	}
	ipRuns, err := destination.Runs(ctx, database.RunKindIPs)
	if err != nil || len(ipRuns) != 1 {
		t.Fatalf("merged IP runs = %#v, %v", ipRuns, err)
	}
	domains, err := destination.IPDomains(ctx, ipRuns[0].ID)
	if err != nil || len(domains) != 1 || domains[0] != "cert.database.example" {
		t.Fatalf("merged IP domains = %#v, %v", domains, err)
	}
	items, err := destination.StoredItems(ctx)
	if err != nil || len(items) != 2 {
		t.Fatalf("merged stored items = %#v, %v", items, err)
	}
	descriptions := make(map[string]string, len(items))
	for _, item := range items {
		descriptions[item.Data] = item.Description
	}
	if descriptions["shared"] != "source description" || descriptions["source-only"] != "from old database" {
		t.Fatalf("merged item descriptions = %#v", descriptions)
	}

	if _, err := Database(ctx, destination, destination.Path()); err == nil {
		t.Fatal("Database() accepted the destination as its own source")
	}
}

func TestImportRequiresExactlyOneSource(t *testing.T) {
	t.Parallel()
	store, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("database.Open(): %v", err)
	}
	defer store.Close()
	if _, err := Import(context.Background(), store, Source{}); err == nil {
		t.Fatal("Import() accepted no source")
	}
	if _, err := Import(context.Background(), store, Source{Folder: "results", Database: "old.db"}); err == nil {
		t.Fatal("Import() accepted two sources")
	}
}
