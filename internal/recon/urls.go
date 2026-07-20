package recon

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

const URLsFilename = "urls.txt"

// ReadUniqueURLs extracts the leading URL from each saved HTTPX output line.
func ReadUniqueURLs(paths ...string) ([]string, error) {
	unique := make(map[string]struct{})
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open HTTPX results: %w", err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 0 {
				continue
			}

			candidate := fields[0]
			parsed, parseErr := url.ParseRequestURI(candidate)
			if parseErr != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				continue
			}
			unique[candidate] = struct{}{}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read HTTPX results: %w", scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close HTTPX results: %w", closeErr)
		}
	}

	urls := make([]string, 0, len(unique))
	for value := range unique {
		urls = append(urls, value)
	}
	sort.Strings(urls)
	return urls, nil
}

// ReadCombinedHTTPX concatenates saved HTTPX artifacts into one text payload.
func ReadCombinedHTTPX(paths ...string) (string, error) {
	var output bytes.Buffer
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read HTTPX results: %w", err)
		}
		output.Write(contents)
		if len(contents) > 0 && contents[len(contents)-1] != '\n' {
			output.WriteByte('\n')
		}
	}
	return output.String(), nil
}
