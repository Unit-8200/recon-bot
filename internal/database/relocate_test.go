package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCopyIfMissingCopiesLegacyDatabaseOnce(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	sourcePath := filepath.Join(root, "checkout", "data", "recon.db")
	targetPath := filepath.Join(root, "config", "recon-bot", "recon.db")
	source, err := Open(sourcePath)
	if err != nil {
		t.Fatalf("Open(source): %v", err)
	}
	if _, err := source.AddStoredItem(context.Background(), "important-data", "keep me"); err != nil {
		t.Fatalf("AddStoredItem(): %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close(source): %v", err)
	}

	copied, err := CopyIfMissing(context.Background(), sourcePath, targetPath)
	if err != nil || !copied {
		t.Fatalf("CopyIfMissing() = %t, %v", copied, err)
	}
	destination, err := Open(targetPath)
	if err != nil {
		t.Fatalf("Open(target): %v", err)
	}
	items, err := destination.StoredItems(context.Background())
	if err != nil {
		t.Fatalf("StoredItems(): %v", err)
	}
	if err := destination.Close(); err != nil {
		t.Fatalf("Close(target): %v", err)
	}
	if len(items) != 1 || items[0].Data != "important-data" || items[0].Description != "keep me" {
		t.Fatalf("copied items = %#v", items)
	}

	copied, err = CopyIfMissing(context.Background(), sourcePath, targetPath)
	if err != nil || copied {
		t.Fatalf("second CopyIfMissing() = %t, %v", copied, err)
	}
}
