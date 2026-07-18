package discordbot

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"discord-bot/internal/recon"

	"github.com/bwmarrin/discordgo"
)

const privateDeliveryCode int64 = 999

func commandDefinitions() []*discordgo.ApplicationCommand {
	adminPermissions := int64(discordgo.PermissionAdministrator)
	guildContexts := []discordgo.InteractionContextType{discordgo.InteractionContextGuild}

	return []*discordgo.ApplicationCommand{
		{
			Name:        "ping",
			Description: "Check whether the bot is online",
		},
		{
			Name:                     "scan",
			Description:              "Enumerate subdomains, probe web services, and save artifacts",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "domain",
					Description: "Authorized root domain, for example example.com",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "code",
					Description: "Optional scan code",
					Required:    false,
				},
			},
		},
		{
			Name:                     "results",
			Description:              "Get the latest completed scan results for a root domain",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "domain",
					Description: "Root domain, for example example.com",
					Required:    true,
				},
			},
		},
	}
}

func (b *Bot) handlePing(session *discordgo.Session, event *discordgo.InteractionCreate) {
	content := fmt.Sprintf("Pong! Gateway latency: %s", session.HeartbeatLatency())
	if err := respond(session, event, content, false); err != nil {
		log.Printf("respond to /ping: %v", err)
	}
}

func (b *Bot) handleScan(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if event.Member == nil || event.Member.User == nil || event.Member.Permissions&discordgo.PermissionAdministrator == 0 {
		if err := respond(session, event, "Only server administrators can use `/scan`.", true); err != nil {
			log.Printf("reject /scan: %v", err)
		}
		return
	}

	domain, ok := stringOption(event.ApplicationCommandData().Options, "domain")
	if !ok {
		if err := respond(session, event, "The `domain` option is required.", true); err != nil {
			log.Printf("validate /scan: %v", err)
		}
		return
	}
	private := integerOption(event.ApplicationCommandData().Options, "code") == privateDeliveryCode

	destination := "this channel"
	if private {
		destination = "your DMs"
	}
	acknowledgement := fmt.Sprintf("Scan started for `%s`. The HTTPX results will be sent to %s when it finishes.", domain, destination)
	if err := respond(session, event, acknowledgement, true); err != nil {
		log.Printf("acknowledge /scan: %v", err)
		return
	}

	parent := b.runContext
	if parent == nil {
		parent = context.Background()
	}
	channelID := event.ChannelID
	userID := event.Member.User.ID
	go b.runScan(parent, session, channelID, userID, domain, private)
}

func (b *Bot) runScan(ctx context.Context, session *discordgo.Session, channelID, userID, domain string, private bool) {
	deliveryChannelID := channelID
	if private {
		directMessage, dmErr := session.UserChannelCreate(userID)
		if dmErr != nil {
			log.Printf("open DM for /scan requester %s: %v", userID, dmErr)
			failure := fmt.Sprintf("<@%s> I couldn't open your DMs, so the private scan was not started.", userID)
			if _, sendErr := session.ChannelMessageSend(channelID, failure); sendErr != nil {
				log.Printf("report private /scan delivery failure: %v", sendErr)
			}
			return
		}
		deliveryChannelID = directMessage.ID
	}

	result, err := b.recon.Run(ctx, domain)
	if ctx.Err() != nil {
		log.Printf("scan for %q stopped during bot shutdown: %v", domain, ctx.Err())
		return
	}
	if err != nil {
		log.Printf("run scan for %q: %v", domain, err)
		content := fmt.Sprintf("<@%s> scan failed for `%s`. Review the bot logs.", userID, domain)
		if result.Directory != "" {
			content = fmt.Sprintf("<@%s> scan stopped for `%s`. Partial artifacts were saved in `%s`.", userID, domain, result.Directory)
		}
		if private {
			content = fmt.Sprintf("Scan failed for `%s`. Review the bot logs.", domain)
			if result.Directory != "" {
				content = fmt.Sprintf("Scan stopped for `%s`. Partial artifacts were saved in `%s`.", domain, result.Directory)
			}
		}
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, content); sendErr != nil {
			log.Printf("report /scan failure: %v", sendErr)
		}
		return
	}

	content := fmt.Sprintf("<@%s> scan complete for `%s`.", userID, result.Domain)
	if private {
		content = fmt.Sprintf("Scan complete for `%s`.", result.Domain)
	}

	httpxFile, err := os.Open(result.HTTPXFile)
	if err != nil {
		log.Printf("open HTTPX results for %q: %v", domain, err)
		content += fmt.Sprintf(" The attachment could not be opened; local artifacts: `%s`.", result.Directory)
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, content); sendErr != nil {
			log.Printf("report /scan attachment failure: %v", sendErr)
		}
		return
	}
	defer httpxFile.Close()

	if _, err := session.ChannelMessageSendComplex(deliveryChannelID, &discordgo.MessageSend{
		Content: content,
		Files: []*discordgo.File{
			{Name: "httpx_results.txt", ContentType: "text/plain; charset=utf-8", Reader: httpxFile},
		},
	}); err != nil {
		log.Printf("publish /scan results for %q: %v", domain, err)
		fallback := fmt.Sprintf("<@%s> scan completed for `%s`, but Discord rejected the HTTPX attachment. Local artifacts: `%s`.", userID, result.Domain, result.Directory)
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, fallback); sendErr != nil {
			log.Printf("report /scan publish failure: %v", sendErr)
		}
	}
}

func (b *Bot) handleResults(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if event.Member == nil || event.Member.User == nil || event.Member.Permissions&discordgo.PermissionAdministrator == 0 {
		if err := respond(session, event, "Only server administrators can use `/results`.", true); err != nil {
			log.Printf("reject /results: %v", err)
		}
		return
	}

	domain, ok := stringOption(event.ApplicationCommandData().Options, "domain")
	if !ok {
		if err := respond(session, event, "The `domain` option is required.", true); err != nil {
			log.Printf("validate /results: %v", err)
		}
		return
	}

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	}); err != nil {
		log.Printf("defer /results response: %v", err)
		return
	}

	result, err := b.recon.Latest(domain)
	if err != nil {
		content := "Could not read previous scan results. Review the bot logs."
		if errors.Is(err, recon.ErrResultsNotFound) {
			content = fmt.Sprintf("No completed scan results found for `%s`.", domain)
		} else {
			log.Printf("find /results for %q: %v", domain, err)
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /results failure: %v", editErr)
		}
		return
	}

	file, err := os.Open(result.HTTPXFile)
	if err != nil {
		log.Printf("open /results file for %q: %v", domain, err)
		content := "The saved HTTPX results could not be opened. Review the bot logs."
		_, _ = session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content})
		return
	}
	defer file.Close()

	content := fmt.Sprintf("Latest scan results for `%s`.", result.Domain)
	if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{
		Content: &content,
		Files: []*discordgo.File{
			{Name: recon.HTTPXFilename, ContentType: "text/plain; charset=utf-8", Reader: file},
		},
	}); err != nil {
		log.Printf("send /results for %q: %v", domain, err)
	}
}

func respond(session *discordgo.Session, event *discordgo.InteractionCreate, content string, ephemeral bool) error {
	data := &discordgo.InteractionResponseData{Content: content}
	if ephemeral {
		data.Flags = discordgo.MessageFlagsEphemeral
	}

	return session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: data,
	})
}

func stringOption(options []*discordgo.ApplicationCommandInteractionDataOption, name string) (string, bool) {
	for _, option := range options {
		if option.Name == name && option.Type == discordgo.ApplicationCommandOptionString {
			value := strings.TrimSpace(option.StringValue())
			return value, value != ""
		}
	}
	return "", false
}

func integerOption(options []*discordgo.ApplicationCommandInteractionDataOption, name string) int64 {
	for _, option := range options {
		if option.Name == name && option.Type == discordgo.ApplicationCommandOptionInteger {
			return option.IntValue()
		}
	}
	return 0
}
