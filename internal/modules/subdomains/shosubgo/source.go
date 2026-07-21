// Package shosubgo retrieves passive DNS subdomains from the Shodan API.
package shosubgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.shodan.io"

var (
	ErrInvalidAPIKey       = errors.New("invalid Shodan API key")
	ErrInsufficientCredits = errors.New("insufficient Shodan query credits")
)

// Source implements Shosubgo's Shodan DNS-domain retrieval as a library adapter.
type Source struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// New creates a Shodan source.
func New(apiKey string) *Source {
	return &Source{
		apiKey:  strings.TrimSpace(apiKey),
		baseURL: defaultBaseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Name identifies this source in logs.
func (*Source) Name() string { return "shosubgo" }

type domainResponse struct {
	Subdomains []string `json:"subdomains"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Enumerate performs the same DNS domain lookup used by Shosubgo and expands
// Shodan's relative names into fully qualified subdomains.
func (s *Source) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if s.apiKey == "" {
		return nil, ErrInvalidAPIKey
	}

	endpoint, err := url.Parse(strings.TrimRight(s.baseURL, "/") + "/dns/domain/" + url.PathEscape(domain))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	query := endpoint.Query()
	query.Set("key", s.apiKey)
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer response.Body.Close()

	limitedBody := io.LimitReader(response.Body, 4<<20)
	if response.StatusCode != http.StatusOK {
		var apiError errorResponse
		_ = json.NewDecoder(limitedBody).Decode(&apiError)
		if response.StatusCode == http.StatusUnauthorized {
			if strings.Contains(strings.ToLower(apiError.Error), "insufficient query credits") {
				return nil, ErrInsufficientCredits
			}
			return nil, ErrInvalidAPIKey
		}
		return nil, fmt.Errorf("Shodan API returned status %d", response.StatusCode)
	}

	var payload domainResponse
	if err := json.NewDecoder(limitedBody).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	results := make([]string, 0, len(payload.Subdomains))
	for _, relativeName := range payload.Subdomains {
		relativeName = strings.ToLower(strings.Trim(strings.TrimSpace(relativeName), "."))
		if relativeName == "" {
			continue
		}
		if relativeName == domain || strings.HasSuffix(relativeName, "."+domain) {
			results = append(results, relativeName)
		} else {
			results = append(results, relativeName+"."+domain)
		}
	}
	return results, nil
}
