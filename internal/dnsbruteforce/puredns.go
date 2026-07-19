// Package dnsbruteforce provides optional active DNS discovery adapters.
package dnsbruteforce

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const wildcardBatchSize = 1_000_000

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// Options configures the Docker-backed PureDNS adapter.
type Options struct {
	Image      string
	Wordlist   string
	Resolvers  string
	RateLimit  int
	Timeout    time.Duration
	DockerPath string
}

// PureDNS runs PureDNS and MassDNS in an isolated container.
type PureDNS struct {
	image      string
	wordlist   string
	resolvers  string
	rateLimit  int
	timeout    time.Duration
	dockerPath string
	gate       chan struct{}
	run        commandRunner
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

// NewPureDNS validates its local dependencies and creates an adapter.
func NewPureDNS(options Options) (*PureDNS, error) {
	options.Image = strings.TrimSpace(options.Image)
	if options.Image == "" {
		return nil, fmt.Errorf("PureDNS image is required")
	}
	if options.RateLimit < 0 {
		return nil, fmt.Errorf("PureDNS rate limit cannot be negative")
	}
	if options.Timeout <= 0 {
		return nil, fmt.Errorf("PureDNS timeout must be positive")
	}

	wordlist, err := requireRegularFile(options.Wordlist, "PureDNS wordlist")
	if err != nil {
		return nil, err
	}
	resolvers, err := requireRegularFile(options.Resolvers, "PureDNS resolvers")
	if err != nil {
		return nil, err
	}

	dockerPath := strings.TrimSpace(options.DockerPath)
	if dockerPath == "" {
		dockerPath, err = exec.LookPath("docker")
		if err != nil {
			return nil, fmt.Errorf("find Docker executable: %w", err)
		}
	}

	return &PureDNS{
		image:      options.Image,
		wordlist:   wordlist,
		resolvers:  resolvers,
		rateLimit:  options.RateLimit,
		timeout:    options.Timeout,
		dockerPath: dockerPath,
		gate:       make(chan struct{}, 1),
		run:        runCommand,
	}, nil
}

// Bruteforce discovers and validates names generated from the configured wordlist.
func (p *PureDNS) Bruteforce(ctx context.Context, rootDomain string) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	cidFile, err := unusedTempPath()
	if err != nil {
		return nil, fmt.Errorf("prepare PureDNS container ID file: %w", err)
	}
	defer os.Remove(cidFile)

	args := []string{
		"run", "--rm",
		"--cidfile", cidFile,
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--mount", bindMount(p.wordlist, "/data/wordlist.txt"),
		"--mount", bindMount(p.resolvers, "/data/resolvers.txt"),
		p.image,
		"bruteforce", "/data/wordlist.txt", rootDomain,
		"--resolvers", "/data/resolvers.txt",
		"--wildcard-batch", strconv.Itoa(wildcardBatchSize),
		"--rate-limit", strconv.Itoa(p.rateLimit),
		"--quiet",
	}
	output, err := p.run(runCtx, p.dockerPath, args...)
	if err != nil {
		if runCtx.Err() != nil {
			p.removeContainer(cidFile)
			return nil, fmt.Errorf("run PureDNS: %w", runCtx.Err())
		}
		return nil, fmt.Errorf("run PureDNS container: %w", err)
	}

	return parseLines(output), nil
}

func unusedTempPath() (string, error) {
	file, err := os.CreateTemp("", "discord-puredns-*.cid")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}

func (p *PureDNS) removeContainer(cidFile string) {
	contents, err := os.ReadFile(cidFile)
	if err != nil {
		return
	}
	containerID := strings.TrimSpace(string(contents))
	if !containerIDPattern.MatchString(containerID) {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(cleanupCtx, p.dockerPath, "rm", "--force", containerID).Run()
}

func requireRegularFile(path, label string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("%s path is required", label)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file", label)
	}
	if strings.Contains(absolute, ",") {
		return "", fmt.Errorf("%s path cannot contain a comma", label)
	}
	return absolute, nil
}

func bindMount(source, target string) string {
	return "type=bind,source=" + source + ",target=" + target + ",readonly"
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("%w: %s", err, message)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func parseLines(output []byte) []string {
	seen := make(map[string]struct{})
	values := make([]string, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		value := strings.ToLower(strings.TrimSpace(scanner.Text()))
		value = strings.TrimSuffix(value, ".")
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}
