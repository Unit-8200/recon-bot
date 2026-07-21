package discordbot

import (
	"testing"

	"github.com/bwmarrin/discordgo"
)

func TestCommandDefinitions(t *testing.T) {
	t.Parallel()

	commands := commandDefinitions()
	if len(commands) != 7 {
		t.Fatalf("got %d commands, want 7", len(commands))
	}
	if commands[1].Name != "subs" {
		t.Fatalf("second command is %q, want subs", commands[1].Name)
	}
	if commands[1].DefaultMemberPermissions == nil || *commands[1].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/subs must default to administrator-only")
	}
	if len(commands[1].Options) != 2 || !commands[1].Options[0].Required || commands[1].Options[1].Required {
		t.Fatal("/subs must have a required domain and optional code")
	}
	if commands[1].Options[1].Name != "code" || commands[1].Options[1].Description != "Optional scan code" {
		t.Fatal("/subs code option must use neutral public wording")
	}
	if len(commands[1].Options[1].Choices) != 0 {
		t.Fatal("/subs code option must not expose its meaning through choices")
	}
	if commands[2].Name != "results" {
		t.Fatalf("third command is %q, want results", commands[2].Name)
	}
	if commands[2].DefaultMemberPermissions == nil || *commands[2].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/results must default to administrator-only")
	}
	if len(commands[2].Options) != 2 || !commands[2].Options[0].Required || commands[2].Options[1].Required {
		t.Fatal("/results must have a required domain and optional urls flag")
	}
	if commands[2].Options[1].Name != "urls" || commands[2].Options[1].Type != discordgo.ApplicationCommandOptionBoolean {
		t.Fatal("/results urls option must be Boolean")
	}
	if commands[3].Name != "domains" {
		t.Fatalf("fourth command is %q, want domains", commands[3].Name)
	}
	if commands[3].DefaultMemberPermissions == nil || *commands[3].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/domains must default to administrator-only")
	}
	if commands[4].Name != "ips" {
		t.Fatalf("fifth command is %q, want ips", commands[4].Name)
	}
	if commands[4].DefaultMemberPermissions == nil || *commands[4].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/ips must default to administrator-only")
	}
	if len(commands[4].Options) != 3 || commands[4].Options[1].Type != discordgo.ApplicationCommandOptionAttachment {
		t.Fatal("/ips must support targets, file attachment, and ports options")
	}
	if commands[5].Name != "add" || len(commands[5].Options) != 2 {
		t.Fatal("sixth command must be /add with data and description options")
	}
	if !commands[5].Options[0].Required || commands[5].Options[0].Name != "data" {
		t.Fatal("/add must require data")
	}
	if commands[5].Options[1].Required || commands[5].Options[1].Name != "description" {
		t.Fatal("/add description must be optional")
	}
	if commands[6].Name != "get" || len(commands[6].Options) != 1 {
		t.Fatal("seventh command must be /get with one optional flag")
	}
	if commands[6].Options[0].Name != "descriptions" || commands[6].Options[0].Type != discordgo.ApplicationCommandOptionBoolean || commands[6].Options[0].Required {
		t.Fatal("/get descriptions must be an optional Boolean")
	}
	for _, command := range commands[5:] {
		if command.DefaultMemberPermissions == nil || *command.DefaultMemberPermissions != discordgo.PermissionAdministrator {
			t.Fatalf("/%s must default to administrator-only", command.Name)
		}
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

func TestBooleanOption(t *testing.T) {
	t.Parallel()

	options := []*discordgo.ApplicationCommandInteractionDataOption{
		{Name: "urls", Type: discordgo.ApplicationCommandOptionBoolean, Value: true},
	}

	if !booleanOption(options, "urls") {
		t.Fatal("booleanOption() = false, want true")
	}
	if booleanOption(options, "missing") {
		t.Fatal("booleanOption() returned true for a missing option")
	}
}
