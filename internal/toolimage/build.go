// Package toolimage builds the Docker image used by PureDNS and Caduceus.
package toolimage

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	Image               = "discord-puredns:2.1.1"
	maximumDownloadSize = 512 << 20

	wordlistURL  = "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/refs/heads/main/n0kovo_subdomains_huge.txt"
	resolversURL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
)

//go:embed Dockerfile
var dockerfile []byte

type commandRunner func(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error

type builder struct {
	cacheDirectory string
	dockerPath     string
	client         *http.Client
	run            commandRunner
}

// Build downloads cached image inputs, builds the tools image, and verifies it.
func Build(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("find Docker executable: %w", err)
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("find user cache directory: %w", err)
	}
	instance := builder{
		cacheDirectory: filepath.Join(cacheRoot, "recon-bot", "tool-image"),
		dockerPath:     dockerPath,
		client:         &http.Client{Timeout: 30 * time.Minute},
		run:            runCommand,
	}
	return instance.build(ctx)
}

func (b builder) build(ctx context.Context) error {
	dataDirectory := filepath.Join(b.cacheDirectory, "data", "puredns")
	if err := os.MkdirAll(dataDirectory, 0o750); err != nil {
		return fmt.Errorf("create tool image cache: %w", err)
	}
	dockerfilePath := filepath.Join(b.cacheDirectory, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, dockerfile, 0o600); err != nil {
		return fmt.Errorf("write tool image Dockerfile: %w", err)
	}

	wordlist := filepath.Join(dataDirectory, "n0kovo_subdomains_huge.txt")
	if err := b.ensureDownload(ctx, wordlistURL, wordlist, 1<<20); err != nil {
		return fmt.Errorf("prepare PureDNS wordlist: %w", err)
	}
	resolvers := filepath.Join(dataDirectory, "resolvers.txt")
	if err := b.ensureDownload(ctx, resolversURL, resolvers, 1<<10); err != nil {
		return fmt.Errorf("prepare PureDNS resolvers: %w", err)
	}

	log.Printf("building Docker tools image %s", Image)
	if err := b.run(ctx, b.dockerPath, []string{"build", "--tag", Image, "--file", dockerfilePath, b.cacheDirectory}, os.Stdout, os.Stderr); err != nil {
		return fmt.Errorf("build Docker tools image: %w", err)
	}
	for _, check := range [][]string{
		{"run", "--rm", "--entrypoint", "test", Image, "-s", "/data/n0kovo_subdomains_huge.txt"},
		{"run", "--rm", "--entrypoint", "test", Image, "-s", "/data/resolvers.txt"},
		{"run", "--rm", "--entrypoint", "caduceus", Image, "-h"},
	} {
		if err := b.run(ctx, b.dockerPath, check, io.Discard, io.Discard); err != nil {
			return fmt.Errorf("verify Docker tools image: %w", err)
		}
	}
	log.Printf("Docker tools image %s is ready", Image)
	return nil
}

func (b builder) ensureDownload(ctx context.Context, sourceURL, destination string, minimumSize int64) error {
	if info, err := os.Stat(destination); err == nil && info.Mode().IsRegular() && info.Size() >= minimumSize {
		return nil
	}
	log.Printf("downloading %s", filepath.Base(destination))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "recon-bot-image-builder")
	response, err := b.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", response.StatusCode)
	}

	temporary, err := os.CreateTemp(filepath.Dir(destination), filepath.Base(destination)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, copyErr := io.Copy(temporary, io.LimitReader(response.Body, maximumDownloadSize+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written < minimumSize {
		return fmt.Errorf("downloaded file is unexpectedly small: %d bytes", written)
	}
	if written > maximumDownloadSize {
		return fmt.Errorf("downloaded file exceeds the %d-byte limit", maximumDownloadSize)
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return nil
}

func runCommand(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}
