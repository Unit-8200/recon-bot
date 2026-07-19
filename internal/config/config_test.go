package config

import (
	"testing"
	"time"
)

func TestPureDNSConfigurationParsers(t *testing.T) {
	t.Setenv("PUREDNS_ENABLED", "true")
	t.Setenv("PUREDNS_PASSIVE_THRESHOLD", "42")
	t.Setenv("PUREDNS_RATE_LIMIT", "2500")
	t.Setenv("PUREDNS_TIMEOUT", "90m")

	enabled, err := parseBool("PUREDNS_ENABLED", false)
	if err != nil || !enabled {
		t.Fatalf("parseBool() = %t, %v", enabled, err)
	}
	threshold, err := parseNonNegativeInt("PUREDNS_PASSIVE_THRESHOLD", 100)
	if err != nil || threshold != 42 {
		t.Fatalf("parseNonNegativeInt(threshold) = %d, %v", threshold, err)
	}
	rateLimit, err := parseNonNegativeInt("PUREDNS_RATE_LIMIT", 5000)
	if err != nil || rateLimit != 2500 {
		t.Fatalf("parseNonNegativeInt(rate) = %d, %v", rateLimit, err)
	}
	timeout, err := parseDuration("PUREDNS_TIMEOUT", 2*time.Hour)
	if err != nil || timeout != 90*time.Minute {
		t.Fatalf("parseDuration() = %s, %v", timeout, err)
	}
}

func TestPureDNSConfigurationRejectsInvalidValues(t *testing.T) {
	t.Setenv("PUREDNS_ENABLED", "sometimes")
	if _, err := parseBool("PUREDNS_ENABLED", false); err == nil {
		t.Fatal("parseBool() accepted an invalid value")
	}

	t.Setenv("PUREDNS_PASSIVE_THRESHOLD", "-1")
	if _, err := parseNonNegativeInt("PUREDNS_PASSIVE_THRESHOLD", 100); err == nil {
		t.Fatal("parseNonNegativeInt() accepted a negative value")
	}

	t.Setenv("PUREDNS_TIMEOUT", "forever")
	if _, err := parseDuration("PUREDNS_TIMEOUT", time.Hour); err == nil {
		t.Fatal("parseDuration() accepted an invalid value")
	}
}
