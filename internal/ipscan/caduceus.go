// Package ipscan provides certificate-based IP and CIDR scanning.
package ipscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	TargetsFilename = "ip_targets.txt"
	ResultsFilename = "caduceus_results.txt"
)

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// Options configures the Docker-backed Caduceus scanner.
type Options struct {
	Image      string
	OutputRoot string
	Timeout    time.Duration
	DockerPath string
}

// Result describes one persisted Caduceus run.
type Result struct {
	Directory   string
	Targets     []string
	Domains     []string
	TargetsFile string
	ResultsFile string
}

// Caduceus extracts certificate domains from IP addresses and CIDR ranges.
type Caduceus struct {
	image      string
	timeout    time.Duration
	dockerPath string
	outputRoot string
	gate       chan struct{}
	run        commandRunner
	now        func() time.Time
}

type commandRunner func(context.Context, string, []string, string) ([]byte, error)

// NewCaduceus validates local configuration and creates a scanner.
func NewCaduceus(options Options) (*Caduceus, error) {
	image := strings.TrimSpace(options.Image)
	if image == "" {
		return nil, fmt.Errorf("Caduceus image is required")
	}
	if options.Timeout <= 0 {
		return nil, fmt.Errorf("Caduceus timeout must be positive")
	}
	outputRoot := strings.TrimSpace(options.OutputRoot)
	if outputRoot == "" {
		return nil, fmt.Errorf("Caduceus results directory is required")
	}

	dockerPath := strings.TrimSpace(options.DockerPath)
	if dockerPath == "" {
		var err error
		dockerPath, err = exec.LookPath("docker")
		if err != nil {
			return nil, fmt.Errorf("find Docker executable: %w", err)
		}
	}

	return &Caduceus{
		image:      image,
		timeout:    options.Timeout,
		dockerPath: dockerPath,
		outputRoot: outputRoot,
		gate:       make(chan struct{}, 1),
		run:        runCommand,
		now:        time.Now,
	}, nil
}

// NormalizeTargets parses, validates, canonicalizes, and deduplicates IP/CIDR input.
func NormalizeTargets(input string) ([]string, error) {
	values := strings.FieldsFunc(input, func(character rune) bool {
		return character == ',' || character == ';' || character == '\n' || character == '\r' || character == '\t' || character == ' '
	})
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				unique[ipv4.String()] = struct{}{}
				continue
			}
			return nil, fmt.Errorf("Caduceus does not support IPv6 target %q", value)
		}
		if ip, network, err := net.ParseCIDR(value); err == nil {
			if ip.To4() == nil {
				return nil, fmt.Errorf("Caduceus does not support IPv6 target %q", value)
			}
			unique[network.String()] = struct{}{}
			continue
		}
		return nil, fmt.Errorf("invalid IP address or CIDR %q", value)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("at least one IP address or CIDR is required")
	}

	targets := make([]string, 0, len(unique))
	for value := range unique {
		targets = append(targets, value)
	}
	sort.Strings(targets)
	return targets, nil
}

// Scan runs Caduceus and persists its validated input and unique certificate names.
func (c *Caduceus) Scan(ctx context.Context, targets []string, ports string) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("context is required")
	}
	normalizedTargets, err := NormalizeTargets(strings.Join(targets, "\n"))
	if err != nil {
		return Result{}, err
	}
	ports, err = normalizePorts(ports)
	if err != nil {
		return Result{}, err
	}

	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}

	directory, err := c.createRunDirectory()
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Directory:   directory,
		Targets:     normalizedTargets,
		TargetsFile: filepath.Join(directory, TargetsFilename),
		ResultsFile: filepath.Join(directory, ResultsFilename),
	}
	if err := writeLines(result.TargetsFile, normalizedTargets); err != nil {
		return result, fmt.Errorf("write Caduceus targets: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cidFile, err := unusedTempPath()
	if err != nil {
		return result, fmt.Errorf("prepare Caduceus container ID file: %w", err)
	}
	defer os.Remove(cidFile)

	args := []string{
		"run", "--rm", "--interactive",
		"--cidfile", cidFile,
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--entrypoint", "caduceus",
		c.image,
		"-p", ports,
	}
	output, err := c.run(runCtx, c.dockerPath, args, strings.Join(normalizedTargets, "\n")+"\n")
	if err != nil {
		if runCtx.Err() != nil {
			c.removeContainer(cidFile)
			return result, fmt.Errorf("run Caduceus: %w", runCtx.Err())
		}
		return result, fmt.Errorf("run Caduceus container: %w", err)
	}
	result.Domains = uniqueLines(output)
	if err := writeLines(result.ResultsFile, result.Domains); err != nil {
		return result, fmt.Errorf("write Caduceus results: %w", err)
	}
	return result, nil
}

func (c *Caduceus) createRunDirectory() (string, error) {
	if err := os.MkdirAll(c.outputRoot, 0o750); err != nil {
		return "", fmt.Errorf("create results root: %w", err)
	}
	baseName := c.now().UTC().Format("20060102T150405.000Z") + "_ips"
	for suffix := 0; ; suffix++ {
		name := baseName
		if suffix > 0 {
			name = fmt.Sprintf("%s_%d", baseName, suffix)
		}
		directory := filepath.Join(c.outputRoot, name)
		err := os.Mkdir(directory, 0o750)
		if err == nil {
			return directory, nil
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("create Caduceus run directory: %w", err)
		}
	}
}

func writeLines(path string, values []string) error {
	contents := ""
	if len(values) > 0 {
		contents = strings.Join(values, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(contents), 0o640)
}

func normalizePorts(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "443", nil
	}
	unique := make(map[int]struct{})
	for _, value := range strings.Split(input, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid TLS port %q", value)
		}
		unique[port] = struct{}{}
	}
	ports := make([]int, 0, len(unique))
	for port := range unique {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	return strings.Join(values, ","), nil
}

func runCommand(ctx context.Context, name string, args []string, stdin string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("%w: %s", err, message)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func uniqueLines(output []byte) []string {
	unique := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		if value := strings.ToLower(strings.TrimSpace(scanner.Text())); value != "" {
			unique[value] = struct{}{}
		}
	}
	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func unusedTempPath() (string, error) {
	file, err := os.CreateTemp("", "discord-caduceus-*.cid")
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

func (c *Caduceus) removeContainer(cidFile string) {
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
	_ = exec.CommandContext(cleanupCtx, c.dockerPath, "rm", "--force", containerID).Run()
}
