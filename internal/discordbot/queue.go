package discordbot

import (
	"fmt"
	"log"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/scanqueue"

	"github.com/bwmarrin/discordgo"
)

func (b *Bot) handleJobs(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if !isAdministrator(event) {
		if err := respond(session, event, "Only server administrators can use `/jobs`.", true); err != nil {
			log.Printf("reject /jobs: %v", err)
		}
		return
	}
	options := event.ApplicationCommandData().Options
	if len(options) != 1 || options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		if err := respond(session, event, "Choose either `/jobs list` or `/jobs cancel`.", true); err != nil {
			log.Printf("validate /jobs subcommand: %v", err)
		}
		return
	}

	switch options[0].Name {
	case "list":
		b.handleJobsList(session, event)
	case "cancel":
		b.handleJobsCancel(session, event, options[0].Options)
	default:
		if err := respond(session, event, "Unknown `/jobs` subcommand.", true); err != nil {
			log.Printf("reject unknown /jobs subcommand: %v", err)
		}
	}
}

func (b *Bot) handleJobsList(session *discordgo.Session, event *discordgo.InteractionCreate) {
	jobs := b.scanQueue.List()
	if len(jobs) == 0 {
		if err := respond(session, event, "No scans are queued or running.", false); err != nil {
			log.Printf("respond to empty /jobs list: %v", err)
		}
		return
	}

	contents := renderJobs(jobs)
	message := fmt.Sprintf("Current scan jobs (%d):\n```text\n%s```", len(jobs), contents)
	if len(message) <= 2000 {
		if err := respond(session, event, message, false); err != nil {
			log.Printf("respond to /jobs list: %v", err)
		}
		return
	}
	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("Current scan jobs (%d).", len(jobs)),
			Files: []*discordgo.File{{
				Name: "jobs.txt", ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(contents),
			}},
		},
	}); err != nil {
		log.Printf("respond to /jobs list: %v", err)
	}
}

func (b *Bot) handleJobsCancel(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	id := integerOption(options, "id")
	if id < 1 {
		if err := respond(session, event, "A valid job `id` is required.", true); err != nil {
			log.Printf("validate /jobs cancel: %v", err)
		}
		return
	}
	if !b.scanQueue.Delete(id) {
		if err := respond(session, event, fmt.Sprintf("No queued or running scan has ID `#%d`.", id), false); err != nil {
			log.Printf("respond to missing /jobs cancel: %v", err)
		}
		return
	}
	content := fmt.Sprintf("Scan `#%d` was cancelled. Its related scan data will be removed.", id)
	if err := respond(session, event, content, false); err != nil {
		log.Printf("respond to /jobs cancel: %v", err)
	}
}

func renderJobs(jobs []scanqueue.Job) string {
	lines := make([]string, 0, len(jobs))
	for _, job := range jobs {
		kind := job.Kind
		switch job.Kind {
		case scanqueue.KindSubs:
			kind = "domain"
		case scanqueue.KindIPs:
			kind = "network"
		}
		lines = append(lines, fmt.Sprintf("#%-4d %-7s %-7s %s", job.ID, job.Status, kind, job.Target))
	}
	return strings.Join(lines, "\n") + "\n"
}
