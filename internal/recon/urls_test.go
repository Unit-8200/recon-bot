package recon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadUniqueURLs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), HTTPXFilename)
	contents := "https://www.example.com [200] [Home]\n" +
		"http://api.example.com:8080 [301] [https://api.example.com]\n" +
		"https://www.example.com [200] [duplicate]\n" +
		"not-a-url [500]\n" +
		"ftp://files.example.com [200]\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	got, err := ReadUniqueURLs(path)
	if err != nil {
		t.Fatalf("ReadUniqueURLs(): %v", err)
	}
	want := []string{"http://api.example.com:8080", "https://www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadUniqueURLs() = %#v, want %#v", got, want)
	}
}

func TestReadUniqueURLsAcrossFilesAndCombineHTTPX(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(first, []byte("https://b.example.com [200]\nhttps://a.example.com [200]"), 0o600); err != nil {
		t.Fatalf("WriteFile(first): %v", err)
	}
	if err := os.WriteFile(second, []byte("https://a.example.com [301]\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(second): %v", err)
	}

	urls, err := ReadUniqueURLs(first, second)
	if err != nil {
		t.Fatalf("ReadUniqueURLs(): %v", err)
	}
	wantURLs := []string{"https://a.example.com", "https://b.example.com"}
	if !reflect.DeepEqual(urls, wantURLs) {
		t.Fatalf("ReadUniqueURLs() = %#v, want %#v", urls, wantURLs)
	}

	combined, err := ReadCombinedHTTPX(first, second)
	if err != nil {
		t.Fatalf("ReadCombinedHTTPX(): %v", err)
	}
	wantCombined := "https://b.example.com [200]\nhttps://a.example.com [200]\nhttps://a.example.com [301]\n"
	if combined != wantCombined {
		t.Fatalf("ReadCombinedHTTPX() = %q, want %q", combined, wantCombined)
	}
}
