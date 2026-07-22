package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsAndImportsRunsIdempotently(t *testing.T) {
	t.Parallel()

	store, err := Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	tables, err := store.stringRows(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	wantTables := []string{"http_probes", "ip_domains", "ip_targets", "runs", "stored_items", "subdomains"}
	if len(tables) != len(wantTables) {
		t.Fatalf("tables = %#v, want %#v", tables, wantTables)
	}
	for index := range wantTables {
		if tables[index] != wantTables[index] {
			t.Fatalf("tables = %#v, want %#v", tables, wantTables)
		}
	}
	timestamp := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id, err := store.CreateRun(ctx, RunKindSubs, "example.com", timestamp)
	if err != nil {
		t.Fatalf("CreateRun(): %v", err)
	}
	if err := store.PutSubdomains(ctx, id, []string{"www.example.com"}, SubdomainStagePassive); err != nil {
		t.Fatalf("PutSubdomains(): %v", err)
	}
	if err := store.PutHTTPProbes(ctx, id, []HTTPProbe{{URL: "https://example.com", StatusCode: 200, Output: "https://example.com [200]"}}); err != nil {
		t.Fatalf("PutHTTPProbes(): %v", err)
	}
	if err := store.FinishRun(ctx, id, RunStatusCompleted, nil); err != nil {
		t.Fatalf("FinishRun(): %v", err)
	}

	legacy := ImportData{
		Run: Run{
			Kind: RunKindIPs, StartedAt: timestamp.Add(time.Hour), Status: RunStatusCompleted, SourcePath: "/legacy/ips",
		},
		IPTargets: []string{"192.0.2.1"},
		IPDomains: []string{"legacy.example"},
	}
	imported, err := store.ImportRun(ctx, legacy)
	if err != nil || !imported {
		t.Fatalf("ImportRun() = %t, %v", imported, err)
	}
	imported, err = store.ImportRun(ctx, legacy)
	if err != nil || imported {
		t.Fatalf("second ImportRun() = %t, %v", imported, err)
	}

	subs, err := store.Runs(ctx, RunKindSubs)
	if err != nil || len(subs) != 1 {
		t.Fatalf("Runs(subs) = %#v, %v", subs, err)
	}
	probes, err := store.HTTPProbes(ctx, id)
	if err != nil || len(probes) != 1 || probes[0].StatusCode != 200 {
		t.Fatalf("HTTPProbes() = %#v, %v", probes, err)
	}
	ips, err := store.Runs(ctx, RunKindIPs)
	if err != nil || len(ips) != 1 || ips[0].SourcePath != "/legacy/ips" {
		t.Fatalf("Runs(ips) = %#v, %v", ips, err)
	}
	targets, err := store.IPTargets(ctx, ips[0].ID)
	if err != nil || len(targets) != 1 || targets[0] != "192.0.2.1" {
		t.Fatalf("IPTargets() = %#v, %v", targets, err)
	}
}

func TestDeleteRunCascadesRelatedScanData(t *testing.T) {
	t.Parallel()

	store, err := Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	runID, err := store.CreateRun(ctx, RunKindSubs, "example.com", time.Now())
	if err != nil {
		t.Fatalf("CreateRun(): %v", err)
	}
	if err := store.PutSubdomains(ctx, runID, []string{"www.example.com"}, SubdomainStageResolved); err != nil {
		t.Fatalf("PutSubdomains(): %v", err)
	}
	if err := store.PutHTTPProbes(ctx, runID, []HTTPProbe{{URL: "https://www.example.com"}}); err != nil {
		t.Fatalf("PutHTTPProbes(): %v", err)
	}
	if err := store.PutIPTargets(ctx, runID, []string{"192.0.2.1"}); err != nil {
		t.Fatalf("PutIPTargets(): %v", err)
	}
	if err := store.PutIPDomains(ctx, runID, []string{"certificate.example.com"}); err != nil {
		t.Fatalf("PutIPDomains(): %v", err)
	}

	if err := store.DeleteRun(ctx, runID); err != nil {
		t.Fatalf("DeleteRun(): %v", err)
	}
	if err := store.DeleteRun(ctx, runID); err != ErrNotFound {
		t.Fatalf("second DeleteRun() = %v, want ErrNotFound", err)
	}
	for _, table := range []string{"runs", "subdomains", "http_probes", "ip_targets", "ip_domains"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+map[string]string{
			"runs": "id", "subdomains": "run_id", "http_probes": "run_id", "ip_targets": "run_id", "ip_domains": "run_id",
		}[table]+` = ?`, runID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after DeleteRun()", table, count)
		}
	}
}
