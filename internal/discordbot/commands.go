package discordbot

import (
	"context"
	"errors"
	"fmt"
	"log"
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
			Name:                     "subs",
			Description:              "Enumerate subdomains, probe web services, and save results",
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
					Description: "Root domain or wildcard, such as * or *example.com",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "urls",
					Description: "Return only unique HTTP and HTTPS URLs",
					Required:    false,
				},
			},
		},
		{
			Name:                     "domains",
			Description:              "List every root domain in the saved scan history",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
		},
		{
			Name:                     "ips",
			Description:              "Extract certificate domains from IP addresses or CIDR ranges",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "targets",
					Description: "Comma or space separated IP addresses and CIDR ranges",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionAttachment,
					Name:        "file",
					Description: "Text file containing one IP address or CIDR per line",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "ports",
					Description: "Comma-separated TLS ports; defaults to 443",
					Required:    false,
				},
			},
		},
		{
			Name:                     "add",
			Description:              "Store a value with an optional description",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "data",
					Description: "Single-line value to store",
					Required:    true,
					MaxLength:   4000,
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "description",
					Description: "Optional context for this value",
					Required:    false,
					MaxLength:   1000,
				},
			},
		},
		{
			Name:                     "get",
			Description:              "Get all manually stored data",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "descriptions",
					Description: "Include optional descriptions in the output",
					Required:    false,
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
	if event.Member == nil || event.Member.User == nil || event.Member.Permissions&discordgo.PermissionAdministrator == 0 {
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
	private := integerOption(event.ApplicationCommandData().Options, "code") == privateDeliveryCode

	destination := "this channel"
	if private {
		destination = "your DMs"
	}
	acknowledgement := fmt.Sprintf("Scan started for `%s`. The HTTPX results will be sent to %s when it finishes.", domain, destination)
	if err := respond(session, event, acknowledgement, private); err != nil {
		log.Printf("acknowledge /subs: %v", err)
		return
	}

	parent := b.runContext
	if parent == nil {
		parent = context.Background()
	}
	channelID := event.ChannelID
	userID := event.Member.User.ID
	go b.runSubs(parent, session, channelID, userID, domain, private)
}

func (b *Bot) runSubs(ctx context.Context, session *discordgo.Session, channelID, userID, domain string, private bool) {
	deliveryChannelID := channelID
	if private {
		directMessage, dmErr := session.UserChannelCreate(userID)
		if dmErr != nil {
			log.Printf("open DM for /subs requester %s: %v", userID, dmErr)
			failure := fmt.Sprintf("<@%s> I couldn't open your DMs, so the private scan was not started.", userID)
			if _, sendErr := session.ChannelMessageSend(channelID, failure); sendErr != nil {
				log.Printf("report private /subs delivery failure: %v", sendErr)
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
		if result.RunID != 0 {
			content = fmt.Sprintf("<@%s> scan stopped for `%s`. Partial scan data was saved in SQLite.", userID, domain)
		}
		if private {
			content = fmt.Sprintf("Scan failed for `%s`. Review the bot logs.", domain)
			if result.RunID != 0 {
				content = fmt.Sprintf("Scan stopped for `%s`. Partial scan data was saved in SQLite.", domain)
			}
		}
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, content); sendErr != nil {
			log.Printf("report /subs failure: %v", sendErr)
		}
		return
	}

	content := fmt.Sprintf("<@%s> scan complete for `%s`.", userID, result.Domain)
	if private {
		content = fmt.Sprintf("Scan complete for `%s`.", result.Domain)
	}

	if _, err := session.ChannelMessageSendComplex(deliveryChannelID, &discordgo.MessageSend{
		Content: content,
		Files: []*discordgo.File{
			{Name: recon.HTTPXFilename, ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(result.HTTPXOutput)},
		},
	}); err != nil {
		log.Printf("publish /subs results for %q: %v", domain, err)
		fallback := fmt.Sprintf("<@%s> scan completed for `%s`, but Discord rejected the HTTPX attachment. The results remain saved in SQLite.", userID, result.Domain)
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, fallback); sendErr != nil {
			log.Printf("report /subs publish failure: %v", sendErr)
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
	urlsOnly := booleanOption(event.ApplicationCommandData().Options, "urls")

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /results response: %v", err)
		return
	}

	results, err := b.recon.Results(domain)
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

	outputs := make([]string, 0, len(results))
	for _, result := range results {
		outputs = append(outputs, result.HTTPXOutput)
	}
	content := fmt.Sprintf("Latest scan results for `%s`.", results[0].Domain)
	if len(results) > 1 || strings.Contains(domain, "*") {
		content = fmt.Sprintf("Scan results matching `%s`.", domain)
	}

	if urlsOnly {
		urls := recon.UniqueURLs(outputs...)

		contents := strings.Join(urls, "\n")
		if contents != "" {
			contents += "\n"
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{
			Content: &content,
			Files: []*discordgo.File{
				{Name: recon.URLsFilename, ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(contents)},
			},
		}); editErr != nil {
			log.Printf("send URL-only /results for %q: %v", domain, editErr)
		}
		return
	}

	combined := recon.CombineHTTPX(outputs...)

	if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{
		Content: &content,
		Files: []*discordgo.File{
			{Name: recon.HTTPXFilename, ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(combined)},
		},
	}); err != nil {
		log.Printf("send /results for %q: %v", domain, err)
	}
}

func (b *Bot) handleDomains(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if event.Member == nil || event.Member.User == nil || event.Member.Permissions&discordgo.PermissionAdministrator == 0 {
		if err := respond(session, event, "Only server administrators can use `/domains`.", true); err != nil {
			log.Printf("reject /domains: %v", err)
		}
		return
	}

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /domains response: %v", err)
		return
	}

	domains, err := b.recon.Domains()
	if err != nil {
		content := "Could not read the scan history. Review the bot logs."
		if errors.Is(err, recon.ErrResultsNotFound) {
			content = "No saved scan history was found."
		} else {
			log.Printf("list /domains: %v", err)
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /domains failure: %v", editErr)
		}
		return
	}

	contents := strings.Join(domains, "\n") + "\n"
	content := "Saved scan root domains."
	if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{
		Content: &content,
		Files: []*discordgo.File{
			{Name: recon.DomainsFilename, ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(contents)},
		},
	}); err != nil {
		log.Printf("send /domains: %v", err)
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

func booleanOption(options []*discordgo.ApplicationCommandInteractionDataOption, name string) bool {
	for _, option := range options {
		if option.Name == name && option.Type == discordgo.ApplicationCommandOptionBoolean {
			return option.BoolValue()
		}
	}
	return false
}
