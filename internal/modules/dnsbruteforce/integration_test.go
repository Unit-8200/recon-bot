package dnsbruteforce

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestPureDNSDockerIntegration(t *testing.T) {
	if os.Getenv("PUREDNS_INTEGRATION") != "1" {
		t.Skip("set PUREDNS_INTEGRATION=1 to run the Docker-backed test")
	}

	directory := t.TempDir()
	wordlist := writeFixture(t, directory, "words.txt", "www\ndefinitely-not-real-puredns-smoke-7f2c91\n")
	resolvers := writeFixture(t, directory, "resolvers.txt", "8.8.8.8\n1.1.1.1\n")
	adapter, err := NewPureDNS(Options{
		Image:     "discord-puredns:2.1.1",
		Wordlist:  wordlist,
		Resolvers: resolvers,
		RateLimit: 50,
		Timeout:   time.Minute,
	})
	if err != nil {
		t.Fatalf("NewPureDNS(): %v", err)
	}

	results, err := adapter.Bruteforce(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Bruteforce(): %v", err)
	}
	if !contains(results, "www.example.com") {
		t.Fatalf("results = %#v, want www.example.com", results)
	}
	if contains(results, "definitely-not-real-puredns-smoke-7f2c91.example.com") {
		t.Fatalf("PureDNS accepted a nonexistent name: %#v", results)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
