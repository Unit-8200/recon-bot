package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Unit-8200/recon-bot/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Execute(ctx); err != nil {
		log.Fatal(err)
	}
}
