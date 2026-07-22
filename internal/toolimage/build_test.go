package toolimage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuilderDownloadsBuildsAndVerifiesImage(t *testing.T) {
	t.Parallel()

	var commands []string
	instance := builder{
		cacheDirectory: t.TempDir(),
		dockerPath:     "/usr/bin/docker",
		run: func(_ context.Context, name string, args []string, _, _ io.Writer) error {
			commands = append(commands, name+" "+strings.Join(args, " "))
			return nil
		},
	}
	// Seed the cache, then exercise the complete build without external network access.
	dataDirectory := filepath.Join(instance.cacheDirectory, "data", "puredns")
	if err := os.MkdirAll(dataDirectory, 0o750); err != nil {
		t.Fatalf("MkdirAll(): %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDirectory, "n0kovo_subdomains_huge.txt"), []byte(strings.Repeat("data\n", 300_000)), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDirectory, "resolvers.txt"), []byte(strings.Repeat("1.1.1.1\n", 200)), 0o600); err != nil {
		t.Fatalf("write resolvers: %v", err)
	}
	if err := instance.build(context.Background()); err != nil {
		t.Fatalf("build(): %v", err)
	}
	if len(commands) != 4 {
		t.Fatalf("commands = %#v", commands)
	}
	if !strings.Contains(commands[0], fmt.Sprintf("build --tag %s", Image)) {
		t.Fatalf("build command = %q", commands[0])
	}
	if !strings.Contains(commands[1], "/data/n0kovo_subdomains_huge.txt") || !strings.Contains(commands[2], "/data/resolvers.txt") || !strings.Contains(commands[3], "caduceus") {
		t.Fatalf("verification commands = %#v", commands[1:])
	}
	if _, err := os.Stat(filepath.Join(instance.cacheDirectory, "Dockerfile")); err != nil {
		t.Fatalf("embedded Dockerfile was not written: %v", err)
	}
}
