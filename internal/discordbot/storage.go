package discordbot

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/database"

	"github.com/bwmarrin/discordgo"
)

const storedDataFilename = "data.txt"

func (b *Bot) handleStorage(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if !isAdministrator(event) {
		if err := respond(session, event, "Only server administrators can use `/storage`.", true); err != nil {
			log.Printf("reject /storage: %v", err)
		}
		return
	}
	options := event.ApplicationCommandData().Options
	if len(options) != 1 || options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		if err := respond(session, event, "Choose either `/storage add` or `/storage list`.", true); err != nil {
			log.Printf("validate /storage subcommand: %v", err)
		}
		return
	}
	switch options[0].Name {
	case "add":
		b.handleStorageAdd(session, event, options[0].Options)
	case "list":
		b.handleStorageList(session, event, options[0].Options)
	default:
		if err := respond(session, event, "Unknown `/storage` subcommand.", true); err != nil {
			log.Printf("reject unknown /storage subcommand: %v", err)
		}
	}
}

func (b *Bot) handleStorageAdd(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	data, ok := stringOption(options, "data")
	if !ok {
		if err := respond(session, event, "The `data` option is required.", true); err != nil {
			log.Printf("validate /storage add: %v", err)
		}
		return
	}
	description, _ := stringOption(options, "description")
	created, err := b.dataStore.AddStoredItem(b.context(), data, description)
	if err != nil {
		log.Printf("store /storage add data: %v", err)
		if respondErr := respond(session, event, fmt.Sprintf("Could not store the data: %v", err), true); respondErr != nil {
			log.Printf("report /storage add failure: %v", respondErr)
		}
		return
	}
	message := "Data stored."
	if !created {
		message = "That data was already stored."
	}
	if err := respond(session, event, message, false); err != nil {
		log.Printf("respond to /storage add: %v", err)
	}
}

func (b *Bot) handleStorageList(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	items, err := b.dataStore.StoredItems(b.context())
	if err != nil {
		log.Printf("read /storage list data: %v", err)
		if respondErr := respond(session, event, "Could not read the stored data. Review the bot logs.", true); respondErr != nil {
			log.Printf("report /storage list failure: %v", respondErr)
		}
		return
	}
	if len(items) == 0 {
		if err := respond(session, event, "No data has been stored yet.", false); err != nil {
			log.Printf("respond to empty /storage list: %v", err)
		}
		return
	}

	includeDescriptions := booleanOption(options, "descriptions")
	contents := renderStoredItems(items, includeDescriptions)
	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "Stored data.",
			Files: []*discordgo.File{{
				Name: storedDataFilename, ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(contents),
			}},
		},
	}); err != nil {
		log.Printf("respond to /storage list: %v", err)
	}
}

func (b *Bot) context() context.Context {
	if b.runContext != nil {
		return b.runContext
	}
	return context.Background()
}

func isAdministrator(event *discordgo.InteractionCreate) bool {
	return event.Member != nil && event.Member.User != nil && event.Member.Permissions&discordgo.PermissionAdministrator != 0
}

func renderStoredItems(items []database.StoredItem, includeDescriptions bool) string {
	lines := make([]string, 0, len(items))
	for _, item := range items {
		line := item.Data
		if includeDescriptions && item.Description != "" {
			line += " — " + item.Description
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
}
