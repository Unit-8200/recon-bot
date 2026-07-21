package recon

import (
	"reflect"
	"testing"
)

func TestReadUniqueURLs(t *testing.T) {
	t.Parallel()

	contents := "https://www.example.com [200] [Home]\n" +
		"http://api.example.com:8080 [301] [https://api.example.com]\n" +
		"https://www.example.com [200] [duplicate]\n" +
		"not-a-url [500]\n" +
		"ftp://files.example.com [200]\n"
	got := UniqueURLs(contents)
	want := []string{"http://api.example.com:8080", "https://www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadUniqueURLs() = %#v, want %#v", got, want)
	}
}

func TestReadUniqueURLsAcrossFilesAndCombineHTTPX(t *testing.T) {
	t.Parallel()

	first := "https://b.example.com [200]\nhttps://a.example.com [200]"
	second := "https://a.example.com [301]\n"

	urls := UniqueURLs(first, second)
	wantURLs := []string{"https://a.example.com", "https://b.example.com"}
	if !reflect.DeepEqual(urls, wantURLs) {
		t.Fatalf("ReadUniqueURLs() = %#v, want %#v", urls, wantURLs)
	}

	combined := CombineHTTPX(first, second)
	wantCombined := "https://b.example.com [200]\nhttps://a.example.com [200]\nhttps://a.example.com [301]\n"
	if combined != wantCombined {
		t.Fatalf("ReadCombinedHTTPX() = %q, want %q", combined, wantCombined)
	}
}
