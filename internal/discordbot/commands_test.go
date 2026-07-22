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
		t.Fatal("second command must be /scan with domain and network subcommands")
	}
	domainScan := scan.Options[0]
	if domainScan.Name != "domain" || domainScan.Type != discordgo.ApplicationCommandOptionSubCommand {
		t.Fatal("/scan domain must be a subcommand")
	}
	if len(domainScan.Options) != 2 || !domainScan.Options[0].Required || domainScan.Options[0].Name != "domain" {
		t.Fatal("/scan domain must require domain and support code")
	}
	if domainScan.Options[1].Name != "code" || domainScan.Options[1].Required || domainScan.Options[1].Description != "Optional scan code" {
		t.Fatal("/scan domain code must be optional and use neutral wording")
	}
	if len(domainScan.Options[1].Choices) != 0 {
		t.Fatal("/scan domain code must not expose its meaning through choices")
	}
	networkScan := scan.Options[1]
	if networkScan.Name != "network" || networkScan.Type != discordgo.ApplicationCommandOptionSubCommand || len(networkScan.Options) != 2 {
		t.Fatal("/scan network must support targets and file")
	}
	if networkScan.Options[0].Name != "targets" || networkScan.Options[1].Name != "file" || networkScan.Options[1].Type != discordgo.ApplicationCommandOptionAttachment {
		t.Fatal("/scan network must accept inline targets or an attachment")
	}

	results := commands[2]
	if results.Name != "results" || len(results.Options) != 2 {
		t.Fatal("third command must be /results with domain and roots subcommands")
	}
	domainResults := results.Options[0]
	if domainResults.Name != "domain" || domainResults.Type != discordgo.ApplicationCommandOptionSubCommand || len(domainResults.Options) != 3 {
		t.Fatal("/results domain must support query, view, and format")
	}
	if domainResults.Options[0].Name != "query" || !domainResults.Options[0].Required {
		t.Fatal("/results domain must require query")
	}
	view := domainResults.Options[1]
	if view.Name != "view" || view.Type != discordgo.ApplicationCommandOptionString || view.Required || len(view.Choices) != 2 {
		t.Fatal("/results domain view must be an optional details/urls choice")
	}
	if view.Choices[0].Value != "details" || view.Choices[1].Value != "urls" {
		t.Fatal("/results domain view choices must be details and urls")
	}
	format := domainResults.Options[2]
	if format.Name != "format" || format.Type != discordgo.ApplicationCommandOptionString || format.Required || len(format.Choices) != 2 {
		t.Fatal("/results domain format must be an optional txt/xlsx choice")
	}
	if format.Choices[0].Value != "txt" || format.Choices[1].Value != "xlsx" {
		t.Fatal("/results domain format choices must be txt and xlsx")
	}
	if results.Options[1].Name != "roots" || results.Options[1].Type != discordgo.ApplicationCommandOptionSubCommand {
		t.Fatal("/results roots must be a subcommand")
	}

	storage := commands[3]
	if storage.Name != "storage" || len(storage.Options) != 2 {
		t.Fatal("fourth command must be /storage with add and list subcommands")
	}
	add := storage.Options[0]
	if add.Name != "add" || len(add.Options) != 2 || add.Options[0].Name != "data" || !add.Options[0].Required {
		t.Fatal("/storage add must require data and support a description")
	}
	if add.Options[1].Name != "description" || add.Options[1].Required {
		t.Fatal("/storage add description must be optional")
	}
	list := storage.Options[1]
	if list.Name != "list" || len(list.Options) != 1 || list.Options[0].Name != "descriptions" || list.Options[0].Type != discordgo.ApplicationCommandOptionBoolean {
		t.Fatal("/storage list must have an optional descriptions Boolean")
	}

	jobs := commands[4]
	if jobs.Name != "jobs" || len(jobs.Options) != 2 {
		t.Fatal("fifth command must be /jobs with list and cancel subcommands")
	}
	if jobs.Options[0].Name != "list" || jobs.Options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		t.Fatal("/jobs list must be a subcommand")
	}
	cancel := jobs.Options[1]
	if cancel.Name != "cancel" || cancel.Type != discordgo.ApplicationCommandOptionSubCommand || len(cancel.Options) != 1 {
		t.Fatal("/jobs cancel must be a subcommand with one option")
	}
	id := cancel.Options[0]
	if id.Name != "id" || id.Type != discordgo.ApplicationCommandOptionInteger || !id.Required || id.MinValue == nil || *id.MinValue != 1 {
		t.Fatal("/jobs cancel must require a positive integer ID")
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
