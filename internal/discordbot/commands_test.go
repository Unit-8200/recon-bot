package discordbot

import (
	"testing"

	"github.com/bwmarrin/discordgo"
)

func TestCommandDefinitions(t *testing.T) {
	t.Parallel()

	commands := commandDefinitions()
	if len(commands) != 3 {
		t.Fatalf("got %d commands, want 3", len(commands))
	}
	if commands[1].Name != "scan" {
		t.Fatalf("second command is %q, want scan", commands[1].Name)
	}
	if commands[1].DefaultMemberPermissions == nil || *commands[1].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/scan must default to administrator-only")
	}
	if len(commands[1].Options) != 2 || !commands[1].Options[0].Required || commands[1].Options[1].Required {
		t.Fatal("/scan must have a required domain and optional code")
	}
	if commands[1].Options[1].Name != "code" || commands[1].Options[1].Description != "Optional scan code" {
		t.Fatal("/scan code option must use neutral public wording")
	}
	if len(commands[1].Options[1].Choices) != 0 {
		t.Fatal("/scan code option must not expose its meaning through choices")
	}
	if commands[2].Name != "results" {
		t.Fatalf("third command is %q, want results", commands[2].Name)
	}
	if commands[2].DefaultMemberPermissions == nil || *commands[2].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/results must default to administrator-only")
	}
}

func TestStringOption(t *testing.T) {
	t.Parallel()

	options := []*discordgo.ApplicationCommandInteractionDataOption{
		{Name: "domain", Type: discordgo.ApplicationCommandOptionString, Value: " example.com "},
	}

	got, ok := stringOption(options, "domain")
	if !ok || got != "example.com" {
		t.Fatalf("stringOption() = %q, %t", got, ok)
	}
}

func TestIntegerOption(t *testing.T) {
	t.Parallel()

	options := []*discordgo.ApplicationCommandInteractionDataOption{
		{Name: "code", Type: discordgo.ApplicationCommandOptionInteger, Value: float64(999)},
	}

	if got := integerOption(options, "code"); got != 999 {
		t.Fatalf("integerOption() = %d, want 999", got)
	}
}
