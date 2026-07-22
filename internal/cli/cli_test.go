package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Unit-8200/recon-bot/internal/migration"
)

func TestCommandsDispatchArguments(t *testing.T) {
	t.Parallel()

	var ranConfig, migratedConfig string
	var migratedSource migration.Source
	buildCalls := 0
	actions := actions{
		run: func(_ context.Context, config string) error {
			ranConfig = config
			return nil
		},
		build: func(context.Context) error {
			buildCalls++
			return nil
		},
		migrate: func(_ context.Context, config string, source migration.Source) (migration.Report, error) {
			migratedConfig = config
			migratedSource = source
			return migration.Report{Imported: 2, Skipped: 1, ItemsImported: 3}, nil
		},
		version: "v1.2.3",
	}

	runRoot := newRoot(actions)
	runRoot.SetArgs([]string{"run", "--config", "/tmp/config.yaml"})
	if err := runRoot.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("run command: %v", err)
	}
	if ranConfig != "/tmp/config.yaml" {
		t.Fatalf("run config = %q", ranConfig)
	}

	buildRoot := newRoot(actions)
	buildRoot.SetArgs([]string{"build"})
	if err := buildRoot.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("build command: %v", err)
	}
	if buildCalls != 1 {
		t.Fatalf("build calls = %d", buildCalls)
	}

	var output bytes.Buffer
	migrateRoot := newRoot(actions)
	migrateRoot.SetOut(&output)
	migrateRoot.SetArgs([]string{"migrate", "--config", "/tmp/config.yaml", "--folder", "results"})
	if err := migrateRoot.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("migrate command: %v", err)
	}
	if migratedConfig != "/tmp/config.yaml" || migratedSource.Folder != "results" || migratedSource.Database != "" {
		t.Fatalf("migrate args = %q, %#v", migratedConfig, migratedSource)
	}
	if !strings.Contains(output.String(), "runs: 2 imported, 1 already imported") ||
		!strings.Contains(output.String(), "stored items: 3 imported") {
		t.Fatalf("migrate output = %q", output.String())
	}

	migrateRoot = newRoot(actions)
	migrateRoot.SetArgs([]string{"migrate", "--config", "/tmp/config.yaml", "--db", "old.db"})
	if err := migrateRoot.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("database migrate command: %v", err)
	}
	if migratedSource.Database != "old.db" || migratedSource.Folder != "" {
		t.Fatalf("database migrate source = %#v", migratedSource)
	}
}

func TestRootProvidesHelpCompletionVersionAndValidation(t *testing.T) {
	t.Parallel()

	actions := actions{
		run:   func(context.Context, string) error { return nil },
		build: func(context.Context) error { return nil },
		migrate: func(context.Context, string, migration.Source) (migration.Report, error) {
			return migration.Report{}, nil
		},
		version: "v9.9.9",
	}
	root := newRoot(actions)
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"--help"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("help command: %v", err)
	}
	for _, expected := range []string{"run", "build", "migrate", "version", "completion"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("help output does not contain %q: %s", expected, output.String())
		}
	}

	missingConfig := newRoot(actions)
	missingConfig.SetArgs([]string{"run"})
	if err := missingConfig.ExecuteContext(context.Background()); err == nil {
		t.Fatal("run without --config unexpectedly succeeded")
	}

	missingSource := newRoot(actions)
	missingSource.SetArgs([]string{"migrate", "--config", "/tmp/config.yaml"})
	if err := missingSource.ExecuteContext(context.Background()); err == nil {
		t.Fatal("migrate without a source unexpectedly succeeded")
	}

	multipleSources := newRoot(actions)
	multipleSources.SetArgs([]string{"migrate", "--config", "/tmp/config.yaml", "--folder", "results", "--db", "old.db"})
	if err := multipleSources.ExecuteContext(context.Background()); err == nil {
		t.Fatal("migrate with both sources unexpectedly succeeded")
	}

	versionRoot := newRoot(actions)
	output.Reset()
	versionRoot.SetOut(&output)
	versionRoot.SetArgs([]string{"version"})
	if err := versionRoot.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("version command: %v", err)
	}
	if output.String() != "v9.9.9\n" {
		t.Fatalf("version output = %q", output.String())
	}
}
