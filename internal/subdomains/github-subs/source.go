// Package githubsubs discovers subdomains in files indexed by GitHub code search.
package githubsubs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultBaseURL   = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
	resultsPerPage   = 100
	maxSearchPages   = 10 // GitHub code search exposes at most the first 1,000 results.
	fileWorkers      = 10
	maxFileSize      = 2 << 20
)

// Source adapts the retrieval flow from github-subdomains: search GitHub code,
// retrieve each matching file, and extract hostnames for the requested domain.
type Source struct {
	tokens  []string
	baseURL string
	client  *http.Client
	next    atomic.Uint64
}

// New creates a GitHub code-search source. Empty and duplicate tokens are ignored.
func New(tokens []string) *Source {
	cleanTokens := make([]string, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if _, exists := seen[token]; exists {
			continue
		}
		seen[token] = struct{}{}
		cleanTokens = append(cleanTokens, token)
	}

	return &Source{
		tokens:  cleanTokens,
		baseURL: defaultBaseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Name identifies this source in logs.
func (*Source) Name() string { return "github-subs" }

type searchResponse struct {
	TotalCount int          `json:"total_count"`
	Items      []searchItem `json:"items"`
}

type searchItem struct {
	URL     string `json:"url"`
	HTMLURL string `json:"html_url"`
}

// Enumerate searches up to GitHub's 1,000-result code-search window and parses
// matching files concurrently. Token rotation is used for every API request.
func (s *Source) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if len(s.tokens) == 0 {
		return nil, fmt.Errorf("GitHub token is required")
	}

	domainPattern := regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+` + regexp.QuoteMeta(domain))
	seenFiles := make(map[string]struct{})
	found := make(map[string]struct{})
	var foundMutex sync.Mutex

	for page, maximumPage := 1, 1; page <= maximumPage; page++ {
		searchResult, err := s.search(ctx, domain, page)
		if err != nil {
			return nil, err
		}
		if page == 1 {
			maximumPage = (searchResult.TotalCount + resultsPerPage - 1) / resultsPerPage
			if maximumPage > maxSearchPages {
				maximumPage = maxSearchPages
			}
			if maximumPage == 0 {
				break
			}
		}

		semaphore := make(chan struct{}, fileWorkers)
		var waitGroup sync.WaitGroup
		for _, item := range searchResult.Items {
			fileURL, authenticated := s.fileURL(item)
			if fileURL == "" {
				continue
			}
			if _, exists := seenFiles[fileURL]; exists {
				continue
			}
			seenFiles[fileURL] = struct{}{}

			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-ctx.Done():
					return
				}

				contents, fetchErr := s.fetchFile(ctx, fileURL, authenticated)
				if fetchErr != nil {
					return
				}
				matches := domainPattern.FindAllString(contents, -1)
				foundMutex.Lock()
				for _, match := range matches {
					found[strings.ToLower(match)] = struct{}{}
				}
				foundMutex.Unlock()
			}()
		}
		waitGroup.Wait()

		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	results := make([]string, 0, len(found))
	for subdomain := range found {
		results = append(results, subdomain)
	}
	sort.Strings(results)
	return results, nil
}

func (s *Source) search(ctx context.Context, domain string, page int) (searchResponse, error) {
	endpoint, err := url.Parse(strings.TrimRight(s.baseURL, "/") + "/search/code")
	if err != nil {
		return searchResponse{}, fmt.Errorf("build code search request: %w", err)
	}
	query := endpoint.Query()
	query.Set("q", `"`+domain+`"`)
	query.Set("per_page", fmt.Sprint(resultsPerPage))
	query.Set("page", fmt.Sprint(page))
	query.Set("sort", "indexed")
	query.Set("order", "desc")
	endpoint.RawQuery = query.Encode()

	response, err := s.doAuthenticated(ctx, endpoint.String(), "application/vnd.github+json")
	if err != nil {
		return searchResponse{}, fmt.Errorf("search GitHub code: %w", err)
	}
	defer response.Body.Close()

	var payload searchResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&payload); err != nil {
		return searchResponse{}, fmt.Errorf("decode GitHub search response: %w", err)
	}
	return payload, nil
}

func (s *Source) fetchFile(ctx context.Context, fileURL string, authenticated bool) (string, error) {
	var response *http.Response
	var err error
	if authenticated {
		response, err = s.doAuthenticated(ctx, fileURL, "application/vnd.github.raw+json")
	} else {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
		if requestErr != nil {
			return "", requestErr
		}
		response, err = s.client.Do(request)
		if err == nil && response.StatusCode != http.StatusOK {
			response.Body.Close()
			return "", fmt.Errorf("raw GitHub content returned status %d", response.StatusCode)
		}
	}
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	contents, err := io.ReadAll(io.LimitReader(response.Body, maxFileSize))
	if err != nil {
		return "", err
	}
	return string(contents), nil
}

func (s *Source) doAuthenticated(ctx context.Context, endpoint, accept string) (*http.Response, error) {
	start := int(s.next.Add(1)-1) % len(s.tokens)
	for attempt := range len(s.tokens) {
		token := s.tokens[(start+attempt)%len(s.tokens)]
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", accept)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
		request.Header.Set("User-Agent", "discord-subdomain-bot")

		response, err := s.client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return response, nil
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusTooManyRequests {
			return nil, fmt.Errorf("GitHub API returned status %d", response.StatusCode)
		}
	}
	return nil, fmt.Errorf("all GitHub tokens were rejected or rate limited")
}

func (s *Source) fileURL(item searchItem) (string, bool) {
	if strings.HasPrefix(item.URL, strings.TrimRight(s.baseURL, "/")+"/") {
		return item.URL, true
	}
	if strings.HasPrefix(item.HTMLURL, "https://github.com/") && strings.Contains(item.HTMLURL, "/blob/") {
		rawURL := strings.Replace(item.HTMLURL, "https://github.com/", "https://raw.githubusercontent.com/", 1)
		return strings.Replace(rawURL, "/blob/", "/", 1), false
	}
	return "", false
}
