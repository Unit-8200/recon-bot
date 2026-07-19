// Package httpprobe probes discovered hosts with ProjectDiscovery HTTPX.
package httpprobe

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	customheader "github.com/projectdiscovery/httpx/common/customheader"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/runner"
)

const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

var probePorts = []string{"80", "443", "8443", "8444", "8080", "3000", "5000"}

var (
	portsOnce       sync.Once
	configuredPorts customport.CustomPorts
	configureErr    error
)

// Result is the persisted subset of HTTPX metadata requested by the workflow.
type Result struct {
	CLIOutput     string    `json:"-"`
	Timestamp     time.Time `json:"timestamp"`
	Input         string    `json:"input"`
	URL           string    `json:"url,omitempty"`
	FinalURL      string    `json:"final_url,omitempty"`
	Scheme        string    `json:"scheme,omitempty"`
	Host          string    `json:"host,omitempty"`
	Port          string    `json:"port,omitempty"`
	StatusCode    int       `json:"status_code,omitempty"`
	Title         string    `json:"title,omitempty"`
	Technologies  []string  `json:"technologies,omitempty"`
	WebServer     string    `json:"web_server,omitempty"`
	IPs           []string  `json:"ips,omitempty"`
	CDN           bool      `json:"cdn"`
	CDNName       string    `json:"cdn_name,omitempty"`
	CDNType       string    `json:"cdn_type,omitempty"`
	ContentLength int       `json:"content_length"`
	ContentType   string    `json:"content_type,omitempty"`
	BodyPreview   string    `json:"body_preview,omitempty"`
	Location      string    `json:"location,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// Prober runs an independent HTTPX runner with immutable process-wide ports.
type Prober struct {
	ports customport.CustomPorts
}

// New creates a prober with the workflow's fixed port set.
func New() (*Prober, error) {
	portsOnce.Do(func() {
		configureErr = configuredPorts.Set(strings.Join(probePorts, ","))
	})
	if configureErr != nil {
		return nil, fmt.Errorf("configure HTTPX ports: %w", configureErr)
	}

	ports := append(customport.CustomPorts(nil), configuredPorts...)
	return &Prober{ports: ports}, nil
}

// Probe runs HTTPX against every target using its normal scheme fallback.
func (p *Prober) Probe(ctx context.Context, targets []string) ([]Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if len(targets) == 0 {
		return []Result{}, nil
	}

	var resultMutex sync.Mutex
	results := make([]Result, 0, len(targets))
	outputFile, err := os.CreateTemp("", "discord-httpx-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create temporary HTTPX output: %w", err)
	}
	outputPath := outputFile.Name()
	if err := outputFile.Close(); err != nil {
		_ = os.Remove(outputPath)
		return nil, fmt.Errorf("close temporary HTTPX output: %w", err)
	}
	defer os.Remove(outputPath)

	options := p.options(targets, func(httpxResult runner.Result) {
		result := resultFromHTTPX(httpxResult)
		resultMutex.Lock()
		results = append(results, result)
		resultMutex.Unlock()
	})
	options.Output = outputPath
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("validate HTTPX options: %w", err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("create HTTPX runner: %w", err)
	}
	httpxRunner.RunEnumeration()
	httpxRunner.Close()

	plainOutput, err := os.ReadFile(outputPath)
	if err != nil {
		return results, fmt.Errorf("read HTTPX plain output: %w", err)
	}
	lines := splitOutputLines(string(plainOutput))
	for index := 0; index < len(results) && index < len(lines); index++ {
		results[index].CLIOutput = lines[index]
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return preferPort443(results), nil
}

// preferPort443 removes a host's port 80 result when that same host has a
// successful port 443 result. Results from all other configured ports remain.
func preferPort443(results []Result) []Result {
	hasPort443 := make(map[string]struct{})
	for _, result := range results {
		if result.Port == "443" && result.Error == "" && result.URL != "" {
			hasPort443[resultKey(result)] = struct{}{}
		}
	}

	filtered := make([]Result, 0, len(results))
	for _, result := range results {
		if result.Port == "80" {
			if _, exists := hasPort443[resultKey(result)]; exists {
				continue
			}
		}
		filtered = append(filtered, result)
	}
	return filtered
}

func resultKey(result Result) string {
	if input := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(result.Input), ".")); input != "" {
		return input
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(result.Host), "."))
}

func (p *Prober) options(targets []string, callback runner.OnResultCallback) runner.Options {
	return runner.Options{
		Methods:                 "GET",
		InputTargetHost:         goflags.StringSlice(targets),
		CustomPorts:             p.ports,
		CustomHeaders:           customheader.CustomHeaders{"User-Agent: " + userAgent},
		Threads:                 15,
		Timeout:                 10,
		Silent:                  true,
		NoColor:                 true,
		FollowHostRedirects:     true,
		StatusCode:              true,
		ExtractTitle:            true,
		TechDetect:              true,
		OutputServerHeader:      true,
		OutputIP:                true,
		OutputCDN:               "true",
		ContentLength:           true,
		OutputContentType:       true,
		ResponseBodyPreviewSize: 100,
		Location:                true,
		DisableUpdateCheck:      true,
		DisableStdin:            true,
		DisableStdout:           true,
		OnResult:                callback,
	}
}

func splitOutputLines(output string) []string {
	output = strings.TrimSuffix(output, "\n")
	if output == "" {
		return nil
	}
	return strings.Split(output, "\n")
}

func resultFromHTTPX(value runner.Result) Result {
	ips := make([]string, 0, len(value.A)+len(value.AAAA))
	ips = append(ips, value.A...)
	ips = append(ips, value.AAAA...)

	result := Result{
		Timestamp:     value.Timestamp,
		Input:         value.Input,
		URL:           value.URL,
		FinalURL:      value.FinalURL,
		Scheme:        value.Scheme,
		Host:          value.Host,
		Port:          value.Port,
		StatusCode:    value.StatusCode,
		Title:         value.Title,
		Technologies:  value.Technologies,
		WebServer:     value.WebServer,
		IPs:           ips,
		CDN:           value.CDN,
		CDNName:       value.CDNName,
		CDNType:       value.CDNType,
		ContentLength: value.ContentLength,
		ContentType:   value.ContentType,
		BodyPreview:   value.BodyPreview,
		Location:      value.Location,
		Error:         value.Error,
	}
	if value.Err != nil {
		result.Error = value.Err.Error()
	}
	return result
}
