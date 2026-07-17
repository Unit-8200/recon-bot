package shosubgo

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
		if request.URL.Path != "/dns/domain/example.com" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if request.URL.Query().Get("key") != "secret" {
			t.Error("API key was not supplied")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"subdomains":["www","api.dev","full.example.com",""]}`)),
			Request:    request,
		}, nil
	})}

	source := New("secret")
	source.client = client
	got, err := source.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate(): %v", err)
	}
	want := []string{"www.example.com", "api.dev.example.com", "full.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Enumerate() = %#v, want %#v", got, want)
	}
}
