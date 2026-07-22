package discordbot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/recon"
	"github.com/Unit-8200/recon-bot/internal/scanqueue"

	"github.com/bwmarrin/discordgo"
)

const privateDeliveryCode int64 = 999

func commandDefinitions() []*discordgo.ApplicationCommand {
	adminPermissions := int64(discordgo.PermissionAdministrator)
	guildContexts := []discordgo.InteractionContextType{discordgo.InteractionContextGuild}
	minimumQueueID := float64(1)

	return []*discordgo.ApplicationCommand{
		{
			Name:        "ping",
			Description: "Check whether the bot is online",
		},
		{
			Name:                     "scan",
			Description:              "Run domain or IP reconnaissance",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "subs",
					Description: "Enumerate subdomains and probe web services",
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
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "ips",
					Description: "Extract domains from IP addresses or CIDR ranges",
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
			Description:              "Retrieve stored data and saved scan information",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "storage",
					Description: "Get values submitted through /add",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionBoolean,
							Name:        "descriptions",
							Description: "Include optional descriptions in the output",
							Required:    false,
						},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "scans",
					Description: "Get saved /scan subs output",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "domain",
							Description: "Root domain or wildcard, such as * or *example.com",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "content",
							Description: "Result content; defaults to full",
							Required:    false,
							Choices: []*discordgo.ApplicationCommandOptionChoice{
								{Name: "full", Value: "full"},
								{Name: "urls", Value: "urls"},
							},
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "format",
							Description: "Attachment format; defaults to txt",
							Required:    false,
							Choices: []*discordgo.ApplicationCommandOptionChoice{
								{Name: "txt", Value: "txt"},
								{Name: "xlsx", Value: "xlsx"},
							},
						},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "roots",
					Description: "List root domains from /scan subs history",
				},
			},
		},
		{
			Name:                     "queue",
			Description:              "List or cancel current scans",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "list",
					Description: "List queued and running scans",
				},
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "delete",
					Description: "Cancel a scan and delete its related data",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionInteger,
							Name:        "id",
							Description: "Queue ID shown by /queue list",
							Required:    true,
							MinValue:    &minimumQueueID,
						},
					},
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
	if !isAdministrator(event) {
		if err := respond(session, event, "Only server administrators can use `/scan`.", true); err != nil {
			log.Printf("reject /scan: %v", err)
		}
		return
	}
	options := event.ApplicationCommandData().Options
	if len(options) != 1 || options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		if err := respond(session, event, "Choose either `/scan subs` or `/scan ips`.", true); err != nil {
			log.Printf("validate /scan subcommand: %v", err)
		}
		return
	}
	switch options[0].Name {
	case "subs":
		b.handleSubs(session, event, options[0].Options)
	case "ips":
		b.handleIPs(session, event, options[0].Options)
	default:
		if err := respond(session, event, "Unknown `/scan` subcommand.", true); err != nil {
			log.Printf("reject unknown /scan subcommand: %v", err)
		}
	}
}

func (b *Bot) handleSubs(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	domain, ok := stringOption(options, "domain")
	if !ok {
		if err := respond(session, event, "The `domain` option is required.", true); err != nil {
			log.Printf("validate /scan subs: %v", err)
		}
		return
	}
	private := integerOption(options, "code") == privateDeliveryCode

	parent := b.context()
	queueID := b.scanQueue.Submit(parent, scanqueue.KindSubs, domain, func(ctx context.Context) int64 {
		return b.runSubs(ctx, session, event.ChannelID, event.Member.User.ID, domain, private)
	})

	destination := "this channel"
	if private {
		destination = "your DMs"
	}
	acknowledgement := fmt.Sprintf("Scan `#%d` queued for `%s`. The HTTPX results will be sent to %s when it finishes.", queueID, domain, destination)
	if err := respond(session, event, acknowledgement, private); err != nil {
		log.Printf("acknowledge /scan subs: %v", err)
		b.scanQueue.Delete(queueID)
		return
	}
}

func (b *Bot) runSubs(ctx context.Context, session *discordgo.Session, channelID, userID, domain string, private bool) int64 {
	deliveryChannelID := channelID
	if private {
		directMessage, dmErr := session.UserChannelCreate(userID)
		if dmErr != nil {
			log.Printf("open DM for /scan subs requester %s: %v", userID, dmErr)
			failure := fmt.Sprintf("<@%s> I couldn't open your DMs, so the private scan was not started.", userID)
			if _, sendErr := session.ChannelMessageSend(channelID, failure); sendErr != nil {
				log.Printf("report private /scan subs delivery failure: %v", sendErr)
			}
			return 0
		}
		deliveryChannelID = directMessage.ID
	}

	result, err := b.recon.Run(ctx, domain)
	if ctx.Err() != nil {
		log.Printf("scan for %q cancelled: %v", domain, ctx.Err())
		return result.RunID
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
			log.Printf("report /scan subs failure: %v", sendErr)
		}
		return result.RunID
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
		log.Printf("publish /scan subs results for %q: %v", domain, err)
		fallback := fmt.Sprintf("<@%s> scan completed for `%s`, but Discord rejected the HTTPX attachment. The results remain saved in SQLite.", userID, result.Domain)
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, fallback); sendErr != nil {
			log.Printf("report /scan subs publish failure: %v", sendErr)
		}
	}
	return result.RunID
}

func (b *Bot) handleGetScans(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	domain, ok := stringOption(options, "domain")
	if !ok {
		if err := respond(session, event, "The `domain` option is required.", true); err != nil {
			log.Printf("validate /get scans: %v", err)
		}
		return
	}
	contentType, hasContentType := stringOption(options, "content")
	if !hasContentType {
		contentType = "full"
	}
	if contentType != "full" && contentType != "urls" {
		if err := respond(session, event, "The `content` option must be `full` or `urls`.", true); err != nil {
			log.Printf("validate /get scans content: %v", err)
		}
		return
	}
	urlsOnly := contentType == "urls"
	format, hasFormat := stringOption(options, "format")
	if !hasFormat {
		format = "txt"
	}
	if format != "txt" && format != "xlsx" {
		if err := respond(session, event, "The `format` option must be `txt` or `xlsx`.", true); err != nil {
			log.Printf("validate /get scans format: %v", err)
		}
		return
	}

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /get scans response: %v", err)
		return
	}

	results, err := b.recon.Results(domain)
	if err != nil {
		content := "Could not read previous scan results. Review the bot logs."
		if errors.Is(err, recon.ErrResultsNotFound) {
			content = fmt.Sprintf("No completed scan results found for `%s`.", domain)
		} else {
			log.Printf("find /get scans for %q: %v", domain, err)
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /get scans failure: %v", editErr)
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
	if format == "xlsx" {
		workbook, workbookErr := scanWorkbook(results, urlsOnly)
		if workbookErr != nil {
			log.Printf("build /get scans spreadsheet for %q: %v", domain, workbookErr)
			failure := "Could not create the XLSX scan results. Review the bot logs."
			if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &failure}); editErr != nil {
				log.Printf("report /get scans spreadsheet failure: %v", editErr)
			}
			return
		}
		filename := httpxSpreadsheetFilename
		if urlsOnly {
			filename = urlsSpreadsheetFilename
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{
			Content: &content,
			Files: []*discordgo.File{
				{Name: filename, ContentType: xlsxContentType, Reader: bytes.NewReader(workbook)},
			},
		}); editErr != nil {
			log.Printf("send XLSX /get scans for %q: %v", domain, editErr)
		}
		return
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
			log.Printf("send URL-only /get scans for %q: %v", domain, editErr)
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
		log.Printf("send /get scans for %q: %v", domain, err)
	}
}

func (b *Bot) handleGetRoots(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /get roots response: %v", err)
		return
	}

	domains, err := b.recon.Domains()
	if err != nil {
		content := "Could not read the scan history. Review the bot logs."
		if errors.Is(err, recon.ErrResultsNotFound) {
			content = "No saved scan history was found."
		} else {
			log.Printf("list /get roots: %v", err)
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /get roots failure: %v", editErr)
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
		log.Printf("send /get roots: %v", err)
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
