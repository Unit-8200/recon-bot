package discordbot

import (
	"testing"

	"github.com/Unit-8200/recon-bot/internal/database"
)

func TestRenderStoredItems(t *testing.T) {
	t.Parallel()

	items := []database.StoredItem{
		{Data: "https://one.example"},
		{Data: "https://two.example", Description: "admin panel"},
	}
	got := renderStoredItems(items, true)
	want := "https://one.example\nhttps://two.example — admin panel\n"
	if got != want {
		t.Fatalf("renderStoredItems() = %q, want %q", got, want)
	}

	got = renderStoredItems(items, false)
	want = "https://one.example\nhttps://two.example\n"
	if got != want {
		t.Fatalf("renderStoredItems() without descriptions = %q, want %q", got, want)
	}
}
