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
	if options.Threads != 15 || options.NoFallback || !options.FollowHostRedirects {
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
