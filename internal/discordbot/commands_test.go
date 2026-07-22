package discordbot

import (
	"testing"

	"github.com/bwmarrin/discordgo"
)

func TestCommandDefinitions(t *testing.T) {
	t.Parallel()

	commands := commandDefinitions()
	if len(commands) != 5 {
		t.Fatalf("got %d commands, want 5", len(commands))
	}
	scan := commands[1]
	if scan.Name != "scan" || len(scan.Options) != 2 {
		t.Fatal("second command must be /scan with subs and ips subcommands")
	}
	if scan.Options[0].Name != "subs" || scan.Options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		t.Fatal("/scan subs must be a subcommand")
	}
	if len(scan.Options[0].Options) != 2 || !scan.Options[0].Options[0].Required || scan.Options[0].Options[0].Name != "domain" {
		t.Fatal("/scan subs must require domain and support code")
	}
	if scan.Options[0].Options[1].Name != "code" || scan.Options[0].Options[1].Required || scan.Options[0].Options[1].Description != "Optional scan code" {
		t.Fatal("/scan subs code must be optional and use neutral wording")
	}
	if len(scan.Options[0].Options[1].Choices) != 0 {
		t.Fatal("/scan subs code must not expose its meaning through choices")
	}
	if scan.Options[1].Name != "ips" || scan.Options[1].Type != discordgo.ApplicationCommandOptionSubCommand || len(scan.Options[1].Options) != 3 {
		t.Fatal("/scan ips must support targets, file, and ports")
	}
	if scan.Options[1].Options[1].Type != discordgo.ApplicationCommandOptionAttachment {
		t.Fatal("/scan ips file must be an attachment")
	}
	if commands[2].Name != "add" || len(commands[2].Options) != 2 {
		t.Fatal("third command must be /add with data and description options")
	}
	if !commands[2].Options[0].Required || commands[2].Options[0].Name != "data" {
		t.Fatal("/add must require data")
	}
	if commands[2].Options[1].Required || commands[2].Options[1].Name != "description" {
		t.Fatal("/add description must be optional")
	}
	if commands[3].Name != "get" || len(commands[3].Options) != 3 {
		t.Fatal("fourth command must be /get with storage, scans, and roots subcommands")
	}
	for index, name := range []string{"storage", "scans", "roots"} {
		option := commands[3].Options[index]
		if option.Type != discordgo.ApplicationCommandOptionSubCommand || option.Name != name {
			t.Fatalf("/get subcommand %d = %q type %d, want %q subcommand", index, option.Name, option.Type, name)
		}
	}
	storage := commands[3].Options[0]
	if len(storage.Options) != 1 || storage.Options[0].Name != "descriptions" || storage.Options[0].Type != discordgo.ApplicationCommandOptionBoolean {
		t.Fatal("/get storage must have an optional descriptions Boolean")
	}
	scans := commands[3].Options[1]
	if len(scans.Options) != 3 || scans.Options[0].Name != "domain" || !scans.Options[0].Required {
		t.Fatal("/get scans must require domain and support content and format")
	}
	content := scans.Options[1]
	if content.Name != "content" || content.Type != discordgo.ApplicationCommandOptionString || content.Required || len(content.Choices) != 2 {
		t.Fatal("/get scans content must be an optional full/urls choice")
	}
	if content.Choices[0].Value != "full" || content.Choices[1].Value != "urls" {
		t.Fatal("/get scans content choices must be full and urls")
	}
	format := scans.Options[2]
	if format.Name != "format" || format.Type != discordgo.ApplicationCommandOptionString || format.Required || len(format.Choices) != 2 {
		t.Fatal("/get scans format must be an optional txt/xlsx choice")
	}
	if format.Choices[0].Value != "txt" || format.Choices[1].Value != "xlsx" {
		t.Fatal("/get scans format choices must be txt and xlsx")
	}
	queue := commands[4]
	if queue.Name != "queue" || len(queue.Options) != 2 {
		t.Fatal("fifth command must be /queue with list and delete subcommands")
	}
	if queue.Options[0].Name != "list" || queue.Options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		t.Fatal("/queue list must be a subcommand")
	}
	deleteCommand := queue.Options[1]
	if deleteCommand.Name != "delete" || deleteCommand.Type != discordgo.ApplicationCommandOptionSubCommand || len(deleteCommand.Options) != 1 {
		t.Fatal("/queue delete must be a subcommand with one option")
	}
	id := deleteCommand.Options[0]
	if id.Name != "id" || id.Type != discordgo.ApplicationCommandOptionInteger || !id.Required || id.MinValue == nil || *id.MinValue != 1 {
		t.Fatal("/queue delete must require a positive integer ID")
	}
	for _, command := range commands[1:] {
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
