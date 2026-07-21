package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestStoredItemsDeduplicateAndUpdateDescriptions(t *testing.T) {
	t.Parallel()

	store, err := Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	created, err := store.AddStoredItem(ctx, " https://example.com ", " initial  description ")
	if err != nil || !created {
		t.Fatalf("first AddStoredItem() = %t, %v", created, err)
	}
	created, err = store.AddStoredItem(ctx, "https://example.com", "updated\ndescription")
	if err != nil || created {
		t.Fatalf("duplicate AddStoredItem() = %t, %v", created, err)
	}

	items, err := store.StoredItems(ctx)
	if err != nil {
		t.Fatalf("StoredItems(): %v", err)
	}
	if len(items) != 1 || items[0].Data != "https://example.com" || items[0].Description != "updated description" {
		t.Fatalf("StoredItems() = %#v", items)
	}
	var scanRuns int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs`).Scan(&scanRuns); err != nil {
		t.Fatalf("count scan runs: %v", err)
	}
	if scanRuns != 0 {
		t.Fatalf("manual storage created %d scan runs", scanRuns)
	}
}

func TestStoredItemsRejectMultilineData(t *testing.T) {
	t.Parallel()

	store, err := Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer store.Close()
	if _, err := store.AddStoredItem(context.Background(), "one\ntwo", ""); err == nil {
		t.Fatal("AddStoredItem() accepted multiline data")
	}
}
