// Package migration imports legacy filesystem artifacts into SQLite.
package migration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Unit-8200/recon-bot/internal/database"
	"github.com/Unit-8200/recon-bot/internal/modules/ipscan"
	"github.com/Unit-8200/recon-bot/internal/modules/subdomains"
	"github.com/Unit-8200/recon-bot/internal/recon"
)

const legacyTimestampLayout = "20060102T150405.000Z"

// Report summarizes one additive migration.
type Report struct {
	Imported      int
	Skipped       int
	Ignored       int
	ItemsImported int
	ItemsSkipped  int
}

// Results imports every recognizable legacy run below folder. Source paths are
// recorded in SQLite, making repeated migration commands idempotent.
func Results(ctx context.Context, store *database.Store, folder string) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("context is required")
	}
	if store == nil {
		return Report{}, fmt.Errorf("database store is required")
	}
	absolute, err := filepath.Abs(strings.TrimSpace(folder))
	if err != nil {
		return Report{}, fmt.Errorf("resolve migration folder: %w", err)
	}
	entries, err := os.ReadDir(absolute)
	if err != nil {
		return Report{}, fmt.Errorf("read migration folder: %w", err)
	}

	report := Report{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		kind, domain, startedAt, ok := parseLegacyDirectory(entry.Name())
		if !ok {
			report.Ignored++
			continue
		}
		directory := filepath.Join(absolute, entry.Name())
		artifactNames := subArtifactNames()
		finalArtifact := recon.HTTPXFilename
		if kind == database.RunKindIPs {
			artifactNames = []string{ipscan.TargetsFilename, ipscan.ResultsFilename}
			finalArtifact = ipscan.ResultsFilename
		}
		artifacts := make(map[string]string)
		for _, name := range artifactNames {
			contents, readErr := os.ReadFile(filepath.Join(directory, name))
			if os.IsNotExist(readErr) {
				continue
			}
			if readErr != nil {
				return report, fmt.Errorf("read legacy artifact %s: %w", filepath.Join(directory, name), readErr)
			}
			artifacts[name] = string(contents)
		}
		if len(artifacts) == 0 {
			report.Ignored++
			continue
		}
		status := database.RunStatusPartial
		if _, exists := artifacts[finalArtifact]; exists {
			status = database.RunStatusCompleted
		}
		data := typedImportData(kind, domain, startedAt, status, directory, artifacts)
		imported, importErr := store.ImportRun(ctx, data)
		if importErr != nil {
			return report, fmt.Errorf("import legacy directory %s: %w", directory, importErr)
		}
		if imported {
			report.Imported++
		} else {
			report.Skipped++
		}
	}
	return report, nil
}

func typedImportData(kind, domain string, startedAt time.Time, status, directory string, artifacts map[string]string) database.ImportData {
	data := database.ImportData{Run: database.Run{
		Kind: kind, Domain: domain, StartedAt: startedAt, Status: status, SourcePath: directory,
	}}
	if kind == database.RunKindIPs {
		data.IPTargets = contentLines(artifacts[ipscan.TargetsFilename])
		data.IPDomains = contentLines(artifacts[ipscan.ResultsFilename])
		return data
	}

	typed := make(map[string]database.Subdomain)
	mark := func(content string, stage string) {
		for _, hostname := range contentLines(content) {
			value := typed[hostname]
			value.Hostname = hostname
			switch stage {
			case database.SubdomainStagePassive:
				value.Passive = true
			case database.SubdomainStageBruteforced:
				value.Bruteforced = true
			case database.SubdomainStageResolved:
				value.Resolved = true
			}
			typed[hostname] = value
		}
	}
	mark(artifacts[recon.SubdomainsFilename], database.SubdomainStageDiscovered)
	mark(artifacts[recon.PassiveFilename], database.SubdomainStagePassive)
	mark(artifacts[recon.PureDNSFilename], database.SubdomainStageBruteforced)
	mark(artifacts[recon.ResolvedFilename], database.SubdomainStageResolved)
	for _, value := range typed {
		data.Subdomains = append(data.Subdomains, value)
	}
	for _, line := range contentLines(artifacts[recon.HTTPXFilename]) {
		data.HTTPProbes = append(data.HTTPProbes, database.ProbeFromOutput(line))
	}
	return data
}

func contentLines(content string) []string {
	var values []string
	for _, value := range strings.Split(content, "\n") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func subArtifactNames() []string {
	return []string{
		recon.PassiveFilename,
		recon.PureDNSFilename,
		recon.SubdomainsFilename,
		recon.ResolvedFilename,
		recon.HTTPXFilename,
	}
}

func parseLegacyDirectory(name string) (kind, domain string, startedAt time.Time, ok bool) {
	if len(name) <= len(legacyTimestampLayout) || name[len(legacyTimestampLayout)] != '_' {
		return "", "", time.Time{}, false
	}
	startedAt, err := time.Parse(legacyTimestampLayout, name[:len(legacyTimestampLayout)])
	if err != nil {
		return "", "", time.Time{}, false
	}
	remainder := name[len(legacyTimestampLayout)+1:]
	if separator := strings.LastIndexByte(remainder, '_'); separator >= 0 {
		if _, err := strconv.ParseUint(remainder[separator+1:], 10, 32); err == nil {
			remainder = remainder[:separator]
		}
	}
	if remainder == "ips" {
		return database.RunKindIPs, "", startedAt, true
	}
	domain, err = subdomains.NormalizeRootDomain(remainder)
	if err != nil {
		return "", "", time.Time{}, false
	}
	return database.RunKindSubs, domain, startedAt, true
}
