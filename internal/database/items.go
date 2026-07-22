package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// StoredItem is one manually submitted value and its optional description.
type StoredItem struct {
	ID          int64
	Data        string
	Description string
	CreatedAt   time.Time
}

// AddStoredItem stores one unique value. A non-empty description updates the
// description of an existing value. The returned Boolean reports a new insert.
func (s *Store) AddStoredItem(ctx context.Context, data, description string) (bool, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return false, fmt.Errorf("data is required")
	}
	if strings.ContainsAny(data, "\r\n") {
		return false, fmt.Errorf("data must be a single line")
	}
	description = strings.Join(strings.Fields(description), " ")

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin stored item save: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO stored_items(data, description, created_at)
		VALUES(?, ?, ?)`, data, description, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, fmt.Errorf("save stored item: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check stored item save: %w", err)
	}
	created := changed > 0
	if !created && description != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE stored_items SET description = ? WHERE data = ?`, description, data); err != nil {
			return false, fmt.Errorf("update stored item description: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit stored item: %w", err)
	}
	return created, nil
}

// ImportStoredItem adds one item from another database while preserving its
// creation time. Existing destination data wins, except that an empty
// destination description may be filled from the source.
func (s *Store) ImportStoredItem(ctx context.Context, item StoredItem) (bool, error) {
	item.Data = strings.TrimSpace(item.Data)
	if item.Data == "" {
		return false, fmt.Errorf("data is required")
	}
	if strings.ContainsAny(item.Data, "\r\n") {
		return false, fmt.Errorf("data must be a single line")
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin stored item import: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO stored_items(data, description, created_at)
		VALUES(?, ?, ?)`, item.Data, item.Description, item.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, fmt.Errorf("import stored item: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check stored item import: %w", err)
	}
	created := changed > 0
	if !created && item.Description != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE stored_items SET description = ?
			WHERE data = ? AND description = ''`, item.Description, item.Data); err != nil {
			return false, fmt.Errorf("merge stored item description: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit stored item import: %w", err)
	}
	return created, nil
}

// StoredItems returns every manually submitted item in insertion order.
func (s *Store) StoredItems(ctx context.Context) ([]StoredItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, data, description, created_at FROM stored_items ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query stored items: %w", err)
	}
	defer rows.Close()

	items := make([]StoredItem, 0)
	for rows.Next() {
		var item StoredItem
		var createdAt string
		if err := rows.Scan(&item.ID, &item.Data, &item.Description, &createdAt); err != nil {
			return nil, fmt.Errorf("scan stored item: %w", err)
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse stored item timestamp: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored items: %w", err)
	}
	return items, nil
}
