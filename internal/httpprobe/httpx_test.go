package httpprobe

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

func TestOptionsMatchRequestedCLI(t *testing.T) {
	prober, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	options := prober.options([]string{"example.com"}, func(runner.Result) {})
	if err := options.ValidateOptions(); err != nil {
		t.Fatalf("ValidateOptions(): %v", err)
	}
	if options.Threads != 20 || options.NoFallback || !options.FollowHostRedirects {
		t.Fatalf("unexpected concurrency/fallback options: %+v", options)
	}
	if !options.NoColor {
		t.Fatal("plain HTTPX output must not contain terminal color codes")
	}
	if !options.StatusCode || !options.ExtractTitle || !options.TechDetect || !options.OutputServerHeader {
		t.Fatal("requested response metadata is not enabled")
	}
	if !options.OutputIP || options.OutputCDN != "true" || !options.ContentLength || !options.OutputContentType {
		t.Fatal("requested network/content metadata is not enabled")
	}
	if options.ResponseBodyPreviewSize != 100 || !options.Location {
		t.Fatal("body preview or redirect location is not enabled")
	}
	if got := []string(options.CustomPorts); !reflect.DeepEqual(got, []string{"80,443,8443,8444,8080,3000,5000"}) {
		t.Fatalf("ports = %#v", got)
	}
}

func TestSplitOutputLinesPreservesResultAlignment(t *testing.T) {
	got := splitOutputLines("first\n\nthird\n")
	want := []string{"first", "", "third"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitOutputLines() = %#v, want %#v", got, want)
	}
}

func TestPreferPort443SuppressesOnlyMatchingPort80Result(t *testing.T) {
	results := []Result{
		{Input: "secure.example.com", Port: "80", URL: "http://secure.example.com"},
		{Input: "secure.example.com", Port: "443", URL: "https://secure.example.com"},
		{Input: "secure.example.com", Port: "8080", URL: "http://secure.example.com:8080"},
		{Input: "http-only.example.com", Port: "80", URL: "http://http-only.example.com"},
		{Input: "broken-tls.example.com", Port: "80", URL: "http://broken-tls.example.com"},
		{Input: "broken-tls.example.com", Port: "443", Error: "connection refused"},
	}

	got := preferPort443(results)
	want := []Result{
		{Input: "secure.example.com", Port: "443", URL: "https://secure.example.com"},
		{Input: "secure.example.com", Port: "8080", URL: "http://secure.example.com:8080"},
		{Input: "http-only.example.com", Port: "80", URL: "http://http-only.example.com"},
		{Input: "broken-tls.example.com", Port: "80", URL: "http://broken-tls.example.com"},
		{Input: "broken-tls.example.com", Port: "443", Error: "connection refused"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preferPort443() = %#v, want %#v", got, want)
	}
}
