package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"discord-bot/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return app.Run(ctx)
	}
	if args[0] != "migrate" || len(args) != 2 {
		return fmt.Errorf("usage: go run . [migrate <folder-path>]")
	}
	report, err := app.Migrate(ctx, args[1])
	if err != nil {
		return err
	}
	log.Printf("migration complete: %d imported, %d already imported, %d ignored", report.Imported, report.Skipped, report.Ignored)
	return nil
}
