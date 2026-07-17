package subdomains

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeSource struct {
	name       string
	candidates []string
	err        error
}

func (s fakeSource) Name() string { return s.name }

func (s fakeSource) Enumerate(context.Context, string) ([]string, error) {
	return s.candidates, s.err
}

func TestFinderConsolidatesSources(t *testing.T) {
	t.Parallel()

	finder := &Finder{sources: []source{
		fakeSource{name: "one", candidates: []string{"API.EXAMPLE.COM", "*.dev.example.com", "example.com"}},
		fakeSource{name: "two", candidates: []string{"api.example.com", "other.test", "deep.dev.example.com"}},
		fakeSource{name: "broken", err: errors.New("unavailable")},
	}}

	got, err := finder.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate(): %v", err)
	}
	want := []string{"api.example.com", "deep.dev.example.com", "dev.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Enumerate() = %#v, want %#v", got, want)
	}
}

func TestFinderFailsWhenAllSourcesFail(t *testing.T) {
	t.Parallel()

	finder := &Finder{sources: []source{
		fakeSource{name: "one", err: errors.New("first")},
		fakeSource{name: "two", err: errors.New("second")},
	}}
	if _, err := finder.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatal("Enumerate() unexpectedly succeeded")
	}
}

func TestNormalizeRootDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "domain", input: "example.com", want: "example.com"},
		{name: "trim and lowercase", input: "  EXAMPLE.COM. ", want: "example.com"},
		{name: "international domain", input: "münich.com", want: "xn--mnich-kva.com"},
		{name: "missing", input: "", wantErr: true},
		{name: "URL", input: "https://example.com", wantErr: true},
		{name: "port", input: "example.com:443", wantErr: true},
		{name: "subdomain", input: "api.example.com", wantErr: true},
		{name: "public suffix", input: "com", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeRootDomain(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizeRootDomain(%q) unexpectedly succeeded with %q", test.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeRootDomain(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("NormalizeRootDomain(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestLoadProviderConfig(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	configPath := filepath.Join(directory, "provider-config.yaml")
	contents := []byte("github:\n  - token-one\n  - token-one\nshodan:\n  - shodan-key\nsecuritytrails: []\n")
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatalf("create provider config: %v", err)
	}

	providers, err := loadProviderConfig(configPath)
	if err != nil {
		t.Fatalf("loadProviderConfig(): %v", err)
	}
	if want := []string{"token-one"}; !reflect.DeepEqual(providers["github"], want) {
		t.Fatalf("github tokens = %#v, want %#v", providers["github"], want)
	}
	if want := []string{"shodan-key"}; !reflect.DeepEqual(providers["shodan"], want) {
		t.Fatalf("shodan keys = %#v, want %#v", providers["shodan"], want)
	}

	if _, err := loadProviderConfig(filepath.Join(directory, "missing.yaml")); err == nil {
		t.Fatal("loadProviderConfig(missing) unexpectedly succeeded")
	}
}
