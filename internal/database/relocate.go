package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CopyIfMissing creates a consistent SQLite copy at target when a legacy
// source exists and the target has not been created yet.
func CopyIfMissing(ctx context.Context, source, target string) (bool, error) {
	if strings.TrimSpace(source) == "" {
		return false, nil
	}
	sourcePath, err := filepath.Abs(source)
	if err != nil {
		return false, fmt.Errorf("resolve legacy database path: %w", err)
	}
	targetPath, err := filepath.Abs(target)
	if err != nil {
		return false, fmt.Errorf("resolve persistent database path: %w", err)
	}
	if sourcePath == targetPath {
		return false, nil
	}
	if _, err := os.Stat(targetPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect persistent database: %w", err)
	}
	info, err := os.Stat(sourcePath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect legacy database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("legacy database is not a regular file: %s", sourcePath)
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
		return false, fmt.Errorf("create persistent database directory: %w", err)
	}

	legacy, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		return false, fmt.Errorf("open legacy database: %w", err)
	}
	defer legacy.Close()
	legacy.SetMaxOpenConns(1)
	escapedTarget := strings.ReplaceAll(targetPath, "'", "''")
	if _, err := legacy.ExecContext(ctx, `VACUUM INTO '`+escapedTarget+`'`); err != nil {
		_ = os.Remove(targetPath)
		return false, fmt.Errorf("copy legacy database: %w", err)
	}
	if err := os.Chmod(targetPath, 0o600); err != nil {
		return false, fmt.Errorf("protect persistent database: %w", err)
	}
	return true, nil
}
