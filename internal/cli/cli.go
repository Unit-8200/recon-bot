// Package cli defines the recon-bot Cobra command tree.
package cli

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/Unit-8200/recon-bot/internal/app"
	"github.com/Unit-8200/recon-bot/internal/migration"
	"github.com/Unit-8200/recon-bot/internal/toolimage"

	"github.com/spf13/cobra"
)

type actions struct {
	run     func(context.Context, string) error
	build   func(context.Context) error
	migrate func(context.Context, string, migration.Source) (migration.Report, error)
	version string
}

// Execute runs the production command tree with the supplied process context.
func Execute(ctx context.Context) error {
	command := newRoot(actions{
		run:     app.Run,
		build:   toolimage.Build,
		migrate: app.Migrate,
		version: buildVersion(),
	})
	command.SetOut(os.Stdout)
	command.SetErr(os.Stderr)
	return command.ExecuteContext(ctx)
}

func newRoot(actions actions) *cobra.Command {
	root := &cobra.Command{
		Use:           "recon-bot",
		Short:         "Discord reconnaissance bot",
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       actions.version,
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(
		newRunCommand(actions.run),
		newBuildCommand(actions.build),
		newMigrateCommand(actions.migrate),
		newVersionCommand(actions.version),
	)
	return root
}

func newRunCommand(run func(context.Context, string) error) *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:   "run",
		Short: "Start the Discord bot",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return run(command.Context(), configPath)
		},
	}
	command.Flags().StringVarP(&configPath, "config", "c", "", "path to the bot YAML configuration")
	must(command.MarkFlagRequired("config"))
	must(command.MarkFlagFilename("config", "yaml", "yml"))
	return command
}

func newBuildCommand(build func(context.Context) error) *cobra.Command {
	return &cobra.Command{
		Use:   "build",
		Short: "Build and verify the PureDNS/Caduceus Docker image",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return build(command.Context())
		},
	}
}

func newMigrateCommand(migrate func(context.Context, string, migration.Source) (migration.Report, error)) *cobra.Command {
	var configPath, folderPath, databasePath string
	command := &cobra.Command{
		Use:   "migrate",
		Short: "Merge a legacy results folder or previous database into SQLite",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			report, err := migrate(command.Context(), configPath, migration.Source{
				Folder: folderPath, Database: databasePath,
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(command.OutOrStdout(),
				"Migration complete: runs: %d imported, %d already imported, %d ignored; stored items: %d imported, %d already present\n",
				report.Imported, report.Skipped, report.Ignored, report.ItemsImported, report.ItemsSkipped)
			return err
		},
	}
	command.Flags().StringVarP(&configPath, "config", "c", "", "path to the bot YAML configuration")
	command.Flags().StringVar(&folderPath, "folder", "", "legacy results folder to import")
	command.Flags().StringVar(&databasePath, "db", "", "previous recon-bot SQLite database to import")
	must(command.MarkFlagRequired("config"))
	must(command.MarkFlagFilename("config", "yaml", "yml"))
	must(command.MarkFlagDirname("folder"))
	must(command.MarkFlagFilename("db", "db", "sqlite", "sqlite3"))
	command.MarkFlagsOneRequired("folder", "db")
	command.MarkFlagsMutuallyExclusive("folder", "db")
	return command
}

func newVersionCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the installed version",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(command.OutOrStdout(), version)
			return err
		},
	}
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "devel"
	}
	return info.Main.Version
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
