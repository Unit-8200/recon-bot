package dnsvalidate

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestResolveFiltersAndSortsHosts(t *testing.T) {
	t.Parallel()

	validator := &Validator{
		workers: 3,
		lookup: func(host string) (bool, error) {
			switch host {
			case "api.example.com", "ipv6.example.com":
				return true, nil
			case "error.example.com":
				return false, errors.New("lookup failed")
			default:
				return false, nil
			}
		},
	}

	got, err := validator.Resolve(context.Background(), []string{
		"missing.example.com",
		"API.EXAMPLE.COM",
		"ipv6.example.com",
		"api.example.com",
		"error.example.com",
	})
	if err != nil {
		t.Fatalf("Resolve(): %v", err)
	}
	want := []string{"api.example.com", "ipv6.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v, want %#v", got, want)
	}
}

func TestResolveRequiresContext(t *testing.T) {
	t.Parallel()

	validator := &Validator{workers: 1, lookup: func(string) (bool, error) { return true, nil }}
	if _, err := validator.Resolve(nil, []string{"example.com"}); err == nil {
		t.Fatal("Resolve(nil) succeeded")
	}
}
