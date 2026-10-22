package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ml0renz0/secretwright/internal/cli"
)

var version = "dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, version))
}
