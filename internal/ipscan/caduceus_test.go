package ipscan

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTargets(t *testing.T) {
	t.Parallel()

	got, err := NormalizeTargets("192.0.2.1, 10.0.0.4/24\n192.0.2.1")
	if err != nil {
		t.Fatalf("NormalizeTargets(): %v", err)
	}
	want := []string{"10.0.0.0/24", "192.0.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeTargets() = %#v, want %#v", got, want)
	}
}

func TestNormalizeTargetsRejectsHostnames(t *testing.T) {
	t.Parallel()
	if _, err := NormalizeTargets("example.com"); err == nil {
		t.Fatal("NormalizeTargets() accepted a hostname")
	}
}

func TestNormalizeTargetsRejectsIPv6(t *testing.T) {
	t.Parallel()
	if _, err := NormalizeTargets("2001:db8::1"); err == nil {
		t.Fatal("NormalizeTargets() accepted IPv6, which Caduceus cannot format")
	}
}

func TestCaduceusScanStreamsTargetsToContainer(t *testing.T) {
	t.Parallel()

	outputRoot := t.TempDir()
	scanner, err := NewCaduceus(Options{Image: "test-image", OutputRoot: outputRoot, Timeout: time.Minute, DockerPath: "/test/docker"})
	if err != nil {
		t.Fatalf("NewCaduceus(): %v", err)
	}
	var args []string
	var stdin string
	scanner.run = func(_ context.Context, _ string, commandArgs []string, commandStdin string) ([]byte, error) {
		args = append([]string(nil), commandArgs...)
		stdin = commandStdin
		return []byte("B.example.com\na.example.com\na.example.com\n"), nil
	}

	scanner.now = func() time.Time { return time.Date(2026, 7, 20, 15, 36, 28, 0, time.UTC) }
	got, err := scanner.Scan(context.Background(), []string{"192.0.2.1", "10.0.0.0/24"}, "8443,443")
	if err != nil {
		t.Fatalf("Scan(): %v", err)
	}
	if !strings.Contains(strings.Join(args, " "), "--entrypoint caduceus test-image -p 443,8443") {
		t.Fatalf("container args = %q", args)
	}
	if stdin != "10.0.0.0/24\n192.0.2.1\n" {
		t.Fatalf("stdin = %q", stdin)
	}
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(got.Domains, want) {
		t.Fatalf("Scan() domains = %#v, want %#v", got.Domains, want)
	}
	if filepath.Base(got.Directory) != "20260720T153628.000Z_ips" {
		t.Fatalf("Scan() directory = %q", got.Directory)
	}
	targetsFile, err := os.ReadFile(got.TargetsFile)
	if err != nil || string(targetsFile) != "10.0.0.0/24\n192.0.2.1\n" {
		t.Fatalf("targets artifact = %q, %v", targetsFile, err)
	}
	resultsFile, err := os.ReadFile(got.ResultsFile)
	if err != nil || string(resultsFile) != "a.example.com\nb.example.com\n" {
		t.Fatalf("results artifact = %q, %v", resultsFile, err)
	}
}
