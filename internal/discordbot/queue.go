package discordbot

import (
	"fmt"
	"log"
	"strings"

	"discord-bot/internal/scanqueue"

	"github.com/bwmarrin/discordgo"
)

func (b *Bot) handleQueue(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if !isAdministrator(event) {
		if err := respond(session, event, "Only server administrators can use `/queue`.", true); err != nil {
			log.Printf("reject /queue: %v", err)
		}
		return
	}
	options := event.ApplicationCommandData().Options
	if len(options) != 1 || options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		if err := respond(session, event, "Choose either `/queue list` or `/queue delete`.", true); err != nil {
			log.Printf("validate /queue subcommand: %v", err)
		}
		return
	}

	switch options[0].Name {
	case "list":
		b.handleQueueList(session, event)
	case "delete":
		b.handleQueueDelete(session, event, options[0].Options)
	default:
		if err := respond(session, event, "Unknown `/queue` subcommand.", true); err != nil {
			log.Printf("reject unknown /queue subcommand: %v", err)
		}
	}
}

func (b *Bot) handleQueueList(session *discordgo.Session, event *discordgo.InteractionCreate) {
	jobs := b.scanQueue.List()
	if len(jobs) == 0 {
		if err := respond(session, event, "No scans are queued or running.", false); err != nil {
			log.Printf("respond to empty /queue list: %v", err)
		}
		return
	}

	contents := renderQueue(jobs)
	message := fmt.Sprintf("Current scan queue (%d):\n```text\n%s```", len(jobs), contents)
	if len(message) <= 2000 {
		if err := respond(session, event, message, false); err != nil {
			log.Printf("respond to /queue list: %v", err)
		}
		return
	}
	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("Current scan queue (%d).", len(jobs)),
			Files: []*discordgo.File{{
				Name: "queue.txt", ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(contents),
			}},
		},
	}); err != nil {
		log.Printf("respond to /queue list: %v", err)
	}
}

func (b *Bot) handleQueueDelete(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	id := integerOption(options, "id")
	if id < 1 {
		if err := respond(session, event, "A valid queue `id` is required.", true); err != nil {
			log.Printf("validate /queue delete: %v", err)
		}
		return
	}
	if !b.scanQueue.Delete(id) {
		if err := respond(session, event, fmt.Sprintf("No queued or running scan has ID `#%d`.", id), false); err != nil {
			log.Printf("respond to missing /queue delete: %v", err)
		}
		return
	}
	content := fmt.Sprintf("Scan `#%d` was cancelled. Its related scan data will be removed.", id)
	if err := respond(session, event, content, false); err != nil {
		log.Printf("respond to /queue delete: %v", err)
	}
}

func renderQueue(jobs []scanqueue.Job) string {
	lines := make([]string, 0, len(jobs))
	for _, job := range jobs {
		lines = append(lines, fmt.Sprintf("#%-4d %-7s %-4s %s", job.ID, job.Status, job.Kind, job.Target))
	}
	return strings.Join(lines, "\n") + "\n"
}
