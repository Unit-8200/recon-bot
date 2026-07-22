package dnsbruteforce

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPureDNSBruteforceBuildsContainerCommandAndParsesOutput(t *testing.T) {
	t.Parallel()

	adapter, err := NewPureDNS(Options{
		Image:      "test-puredns:2.1.1",
		RateLimit:  1234,
		Timeout:    time.Minute,
		DockerPath: "/test/docker",
	})
	if err != nil {
		t.Fatalf("NewPureDNS(): %v", err)
	}

	var commandName string
	var commandArgs []string
	adapter.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		commandName = name
		commandArgs = append([]string(nil), args...)
		return []byte("WWW.Example.com.\napi.example.com\nwww.example.com\n"), nil
	}

	values, err := adapter.Bruteforce(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Bruteforce(): %v", err)
	}
	if commandName != "/test/docker" {
		t.Fatalf("command = %q", commandName)
	}
	joined := strings.Join(commandArgs, " ")
	for _, expected := range []string{
		"run --rm",
		"--user",
		"test-puredns:2.1.1 bruteforce /data/n0kovo_subdomains_huge.txt example.com",
		"--resolvers /data/resolvers.txt",
		"--wildcard-batch 1000000",
		"--rate-limit 1234",
		"--quiet",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("command args %q do not contain %q", joined, expected)
		}
	}
	if strings.Contains(joined, "--mount") {
		t.Fatalf("production PureDNS command unexpectedly mounts host data: %q", joined)
	}
	want := []string{"www.example.com", "api.example.com"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("values = %#v, want %#v", values, want)
	}
}

func writeFixture(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	return path
}
