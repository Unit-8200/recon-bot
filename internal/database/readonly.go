package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var requiredTables = []string{
	"runs",
	"subdomains",
	"http_probes",
	"ip_targets",
	"ip_domains",
	"stored_items",
}

// OpenReadOnly opens an existing recon-bot database without initializing or
// otherwise modifying it. It is intended for database-to-database imports.
func OpenReadOnly(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("source database path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve source database path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("stat source database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("source database is not a regular file: %s", absolute)
	}

	uri := (&url.URL{Scheme: "file", Path: absolute}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open source SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, path: absolute}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open source SQLite database: %w", err)
	}
	if err := store.validateImportSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) validateImportSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return fmt.Errorf("inspect source database schema: %w", err)
	}
	defer rows.Close()
	found := make(map[string]bool, len(requiredTables))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("inspect source database schema: %w", err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect source database schema: %w", err)
	}
	for _, name := range requiredTables {
		if !found[name] {
			return fmt.Errorf("source database is not a supported recon-bot database: missing table %q", name)
		}
	}
	return nil
}
