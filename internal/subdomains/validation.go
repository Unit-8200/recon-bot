package subdomains

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// NormalizeRootDomain validates and canonicalizes a registrable root domain.
func NormalizeRootDomain(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if domain == "" {
		return "", fmt.Errorf("root domain is required")
	}
	if strings.ContainsAny(domain, "/:@") {
		return "", fmt.Errorf("root domain must be a hostname without a scheme, port, or path")
	}

	asciiDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("invalid root domain %q: %w", value, err)
	}

	registrableDomain, err := publicsuffix.EffectiveTLDPlusOne(asciiDomain)
	if err != nil {
		return "", fmt.Errorf("invalid root domain %q: %w", value, err)
	}
	if registrableDomain != asciiDomain {
		return "", fmt.Errorf("%q is not a root domain; try %q", value, registrableDomain)
	}

	return asciiDomain, nil
}

func normalizeCandidate(value, rootDomain string) (string, bool) {
	candidate := strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	candidate = strings.TrimPrefix(candidate, "*.")
	if candidate == "" || candidate == rootDomain || !strings.HasSuffix(candidate, "."+rootDomain) {
		return "", false
	}

	asciiCandidate, err := idna.Lookup.ToASCII(candidate)
	if err != nil || asciiCandidate == rootDomain || !strings.HasSuffix(asciiCandidate, "."+rootDomain) {
		return "", false
	}
	for _, label := range strings.Split(asciiCandidate, ".") {
		if !validLabel(label) {
			return "", false
		}
	}

	return asciiCandidate, true
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
