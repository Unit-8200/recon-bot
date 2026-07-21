package recon

import (
	"bufio"
	"bytes"
	"net/url"
	"sort"
	"strings"
)

const URLsFilename = "urls.txt"

// UniqueURLs extracts the leading URL from each HTTPX output line.
func UniqueURLs(outputs ...string) []string {
	unique := make(map[string]struct{})
	for _, output := range outputs {
		scanner := bufio.NewScanner(strings.NewReader(output))
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
	}

	urls := make([]string, 0, len(unique))
	for value := range unique {
		urls = append(urls, value)
	}
	sort.Strings(urls)
	return urls
}

// CombineHTTPX concatenates rendered HTTPX results into one text payload.
func CombineHTTPX(outputs ...string) string {
	var output bytes.Buffer
	for _, contents := range outputs {
		output.WriteString(contents)
		if contents != "" && contents[len(contents)-1] != '\n' {
			output.WriteByte('\n')
		}
	}
	return output.String()
}
