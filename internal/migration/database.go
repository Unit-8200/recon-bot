package migration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/database"
)

// Database merges runs and manually stored items from a previous recon-bot
// SQLite database. Each source run receives a stable identity, so importing the
// same database again skips it instead of duplicating it.
func Database(ctx context.Context, destination *database.Store, path string) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("context is required")
	}
	if destination == nil {
		return Report{}, fmt.Errorf("database store is required")
	}
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return Report{}, fmt.Errorf("resolve source database path: %w", err)
	}
	if sameDatabase(destination.Path(), absolute) {
		return Report{}, fmt.Errorf("source database and destination database are the same file")
	}

	source, err := database.OpenReadOnly(absolute)
	if err != nil {
		return Report{}, err
	}
	defer source.Close()

	report := Report{}
	for _, kind := range []string{database.RunKindSubs, database.RunKindIPs} {
		runs, queryErr := source.Runs(ctx, kind)
		if queryErr != nil {
			return report, fmt.Errorf("read source %s runs: %w", kind, queryErr)
		}
		for _, run := range runs {
			data, readErr := readRun(ctx, source, run)
			if readErr != nil {
				return report, readErr
			}
			if data.Run.SourcePath == "" {
				data.Run.SourcePath = fmt.Sprintf("sqlite:%s#run:%d", absolute, run.ID)
			}
			imported, importErr := destination.ImportRun(ctx, data)
			if importErr != nil {
				return report, fmt.Errorf("import source run %d: %w", run.ID, importErr)
			}
			if imported {
				report.Imported++
			} else {
				report.Skipped++
			}
		}
	}

	items, err := source.StoredItems(ctx)
	if err != nil {
		return report, fmt.Errorf("read source stored items: %w", err)
	}
	for _, item := range items {
		imported, importErr := destination.ImportStoredItem(ctx, item)
		if importErr != nil {
			return report, fmt.Errorf("import stored item %d: %w", item.ID, importErr)
		}
		if imported {
			report.ItemsImported++
		} else {
			report.ItemsSkipped++
		}
	}
	return report, nil
}

func readRun(ctx context.Context, source *database.Store, run database.Run) (database.ImportData, error) {
	data := database.ImportData{Run: run}
	var err error
	switch run.Kind {
	case database.RunKindSubs:
		data.Subdomains, err = source.Subdomains(ctx, run.ID)
		if err == nil {
			data.HTTPProbes, err = source.HTTPProbes(ctx, run.ID)
		}
	case database.RunKindIPs:
		data.IPTargets, err = source.IPTargets(ctx, run.ID)
		if err == nil {
			data.IPDomains, err = source.IPDomains(ctx, run.ID)
		}
	default:
		return database.ImportData{}, fmt.Errorf("source run %d has unsupported kind %q", run.ID, run.Kind)
	}
	if err != nil {
		return database.ImportData{}, fmt.Errorf("read source run %d data: %w", run.ID, err)
	}
	return data, nil
}

func sameDatabase(destination, source string) bool {
	destination, destinationErr := filepath.Abs(destination)
	source, sourceErr := filepath.Abs(source)
	if destinationErr == nil && sourceErr == nil && destination == source {
		return true
	}
	destinationInfo, destinationErr := os.Stat(destination)
	sourceInfo, sourceErr := os.Stat(source)
	return destinationErr == nil && sourceErr == nil && os.SameFile(destinationInfo, sourceInfo)
}
