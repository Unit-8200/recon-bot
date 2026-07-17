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
	if commands[1].Name != "subs" {
		t.Fatalf("second command is %q, want subs", commands[1].Name)
	}
	if commands[1].DefaultMemberPermissions == nil || *commands[1].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/subs must default to administrator-only")
	}
	if len(commands[1].Options) != 1 || !commands[1].Options[0].Required {
		t.Fatal("/subs must have one required domain option")
	}
	if commands[2].Name != "scan" {
		t.Fatalf("third command is %q, want scan", commands[2].Name)
	}
	if commands[2].DefaultMemberPermissions == nil || *commands[2].DefaultMemberPermissions != discordgo.PermissionAdministrator {
		t.Fatal("/scan must default to administrator-only")
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
