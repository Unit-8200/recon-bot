package migration

import (
	"context"
	"fmt"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/database"
)

// Source identifies exactly one supported migration input.
type Source struct {
	Folder   string
	Database string
}

// Import merges the selected source into store without deleting existing data.
func Import(ctx context.Context, store *database.Store, source Source) (Report, error) {
	source.Folder = strings.TrimSpace(source.Folder)
	source.Database = strings.TrimSpace(source.Database)
	if (source.Folder == "") == (source.Database == "") {
		return Report{}, fmt.Errorf("exactly one migration source is required: --folder or --db")
	}
	if source.Folder != "" {
		return Results(ctx, store, source.Folder)
	}
	return Database(ctx, store, source.Database)
}
