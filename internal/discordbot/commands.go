package discordbot

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// /subs still edits its deferred interaction response, so keep that passive-only
// command below Discord's interaction-token window. /scan runs in the background.
const passiveEnumerationTimeout = 10 * time.Minute

func commandDefinitions() []*discordgo.ApplicationCommand {
	adminPermissions := int64(discordgo.PermissionAdministrator)
	guildContexts := []discordgo.InteractionContextType{discordgo.InteractionContextGuild}

	return []*discordgo.ApplicationCommand{
		{
			Name:        "ping",
			Description: "Check whether the bot is online",
		},
		{
			Name:                     "subs",
			Description:              "Passively enumerate subdomains for an authorized root domain",
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

func (b *Bot) handleSubs(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if event.Member == nil || event.Member.Permissions&discordgo.PermissionAdministrator == 0 {
		if err := respond(session, event, "Only server administrators can use `/subs`.", true); err != nil {
			log.Printf("reject /subs: %v", err)
		}
		return
	}

	domain, ok := stringOption(event.ApplicationCommandData().Options, "domain")
	if !ok {
		if err := respond(session, event, "The `domain` option is required.", true); err != nil {
			log.Printf("validate /subs: %v", err)
		}
		return
	}

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	}); err != nil {
		log.Printf("defer /subs response: %v", err)
		return
	}

	parent := b.runContext
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, passiveEnumerationTimeout)
	defer cancel()

	results, err := b.finder.Enumerate(ctx, domain)
	if err != nil {
		log.Printf("enumerate subdomains for %q: %v", domain, err)
		content := "Subdomain enumeration failed. Check that the value is a root domain and review the bot logs."
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /subs failure: %v", editErr)
		}
		return
	}

	if len(results) == 0 {
		content := fmt.Sprintf("No subdomains were found for `%s`.", domain)
		if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); err != nil {
			log.Printf("edit empty /subs response: %v", err)
		}
		return
	}

	content := fmt.Sprintf("Found **%d** unique subdomains for `%s`.", len(results), domain)
	resultFile := strings.NewReader(strings.Join(results, "\n") + "\n")
	if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{
		Content: &content,
		Files: []*discordgo.File{
			{Name: "subdomains.txt", ContentType: "text/plain; charset=utf-8", Reader: resultFile},
		},
	}); err != nil {
		log.Printf("send /subs results: %v", err)
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

	acknowledgement := fmt.Sprintf("Scan started for `%s`. The HTTPX results will be posted in this channel when it finishes.", domain)
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
	go b.runScan(parent, session, channelID, userID, domain)
}

func (b *Bot) runScan(ctx context.Context, session *discordgo.Session, channelID, userID, domain string) {
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
		if _, sendErr := session.ChannelMessageSend(channelID, content); sendErr != nil {
			log.Printf("report /scan failure: %v", sendErr)
		}
		return
	}

	content := fmt.Sprintf("<@%s> scan complete for `%s`.", userID, result.Domain)

	httpxFile, err := os.Open(result.HTTPXFile)
	if err != nil {
		log.Printf("open HTTPX results for %q: %v", domain, err)
		content += fmt.Sprintf(" The attachment could not be opened; local artifacts: `%s`.", result.Directory)
		if _, sendErr := session.ChannelMessageSend(channelID, content); sendErr != nil {
			log.Printf("report /scan attachment failure: %v", sendErr)
		}
		return
	}
	defer httpxFile.Close()

	if _, err := session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: content,
		Files: []*discordgo.File{
			{Name: "httpx_results.txt", ContentType: "text/plain; charset=utf-8", Reader: httpxFile},
		},
	}); err != nil {
		log.Printf("publish /scan results for %q: %v", domain, err)
		fallback := fmt.Sprintf("<@%s> scan completed for `%s`, but Discord rejected the HTTPX attachment. Local artifacts: `%s`.", userID, result.Domain, result.Directory)
		if _, sendErr := session.ChannelMessageSend(channelID, fallback); sendErr != nil {
			log.Printf("report /scan publish failure: %v", sendErr)
		}
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
