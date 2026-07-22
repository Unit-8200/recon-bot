package ipscan

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Unit-8200/recon-bot/internal/database"
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

	store, err := database.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatalf("database.Open(): %v", err)
	}
	defer store.Close()
	scanner, err := NewCaduceus(Options{Image: "test-image", Store: store, Timeout: time.Minute, DockerPath: "/test/docker"})
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
	runs, err := store.Runs(context.Background(), database.RunKindIPs)
	if err != nil || len(runs) != 1 {
		t.Fatalf("Runs() = %#v, %v", runs, err)
	}
	targets, err := store.IPTargets(context.Background(), runs[0].ID)
	if err != nil || !reflect.DeepEqual(targets, []string{"10.0.0.0/24", "192.0.2.1"}) {
		t.Fatalf("stored targets = %#v, %v", targets, err)
	}
	domains, err := store.IPDomains(context.Background(), runs[0].ID)
	if err != nil || !reflect.DeepEqual(domains, want) {
		t.Fatalf("stored IP domains = %#v, %v", domains, err)
	}
}
