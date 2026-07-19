// Package dnsvalidate filters discovered hostnames through ProjectDiscovery DNSX.
package dnsvalidate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

const defaultWorkers = 50

// Validator resolves hostnames concurrently before HTTP probing.
type Validator struct {
	workers int
	lookup  func(string) (bool, error)
}

// New creates a DNSX validator that accepts hosts with an A or AAAA record.
func New() (*Validator, error) {
	options := dnsx.DefaultOptions
	options.MaxRetries = 2
	options.QuestionTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	client, err := dnsx.New(options)
	if err != nil {
		return nil, fmt.Errorf("create DNSX client: %w", err)
	}

	return &Validator{
		workers: defaultWorkers,
		lookup: func(host string) (bool, error) {
			response, err := client.QueryMultiple(host)
			if err != nil {
				return false, err
			}
			return response != nil && (len(response.A) > 0 || len(response.AAAA) > 0), nil
		},
	}, nil
}

// Resolve returns a unique, sorted list of hosts that currently resolve.
func (v *Validator) Resolve(ctx context.Context, targets []string) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if v == nil || v.lookup == nil || v.workers < 1 {
		return nil, fmt.Errorf("DNS validator is not initialized")
	}

	unique := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		target = strings.ToLower(strings.TrimSpace(target))
		if target != "" {
			unique[target] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return []string{}, nil
	}

	jobs := make(chan string)
	resolved := make(chan string)
	workerCount := min(v.workers, len(unique))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-jobs:
					if !ok {
						return
					}
					resolves, _ := v.lookup(target)
					if !resolves {
						continue
					}
					select {
					case resolved <- target:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for target := range unique {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(resolved)
	}()

	results := make([]string, 0, len(unique))
	for target := range resolved {
		results = append(results, target)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Strings(results)
	return results, nil
}
