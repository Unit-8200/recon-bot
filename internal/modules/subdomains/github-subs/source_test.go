package githubsubs

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestEnumerate(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Error("request did not contain the GitHub token")
		}
		var body string
		switch request.URL.Path {
		case "/search/code":
			body = `{"total_count":1,"items":[{"url":"https://api.github.test/repos/acme/repo/contents/config"}]}`
		case "/repos/acme/repo/contents/config":
			body = "API.EXAMPLE.COM api.example.com invalid_example.com deeper.dev.example.com"
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    request,
		}, nil
	})}

	source := New([]string{"token"})
	source.baseURL = "https://api.github.test"
	source.client = client
	got, err := source.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate(): %v", err)
	}
	want := []string{"api.example.com", "deeper.dev.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Enumerate() = %#v, want %#v", got, want)
	}
}
