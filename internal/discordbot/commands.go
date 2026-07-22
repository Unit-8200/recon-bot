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
	minimumJobID := float64(1)

	return []*discordgo.ApplicationCommand{
		{
			Name:        "ping",
			Description: "Check whether the bot is online",
		},
		{
			Name:                     "scan",
			Description:              "Run domain or network reconnaissance",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "domain",
					Description: "Discover subdomains and live web services",
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
					Name:        "network",
					Description: "Discover certificate domains from IPs and CIDRs",
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
					},
				},
			},
		},
		{
			Name:                     "results",
			Description:              "Retrieve saved domain reconnaissance",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "domain",
					Description: "Get the latest saved domain scan results",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "query",
							Description: "Root domain or wildcard, such as * or *example.com",
							Required:    true,
						},
						{
							Type:        discordgo.ApplicationCommandOptionString,
							Name:        "view",
							Description: "Result view; defaults to details",
							Required:    false,
							Choices: []*discordgo.ApplicationCommandOptionChoice{
								{Name: "details", Value: "details"},
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
					Description: "List root domains from scan history",
				},
			},
		},
		{
			Name:                     "storage",
			Description:              "Manage standalone shared data",
			DefaultMemberPermissions: &adminPermissions,
			Contexts:                 &guildContexts,
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "add",
					Description: "Store a value with optional context",
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
					Type:        discordgo.ApplicationCommandOptionSubCommand,
					Name:        "list",
					Description: "List stored values",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionBoolean,
							Name:        "descriptions",
							Description: "Include optional descriptions in the output",
							Required:    false,
						},
					},
				},
			},
		},
		{
			Name:                     "jobs",
			Description:              "List or cancel queued and running scans",
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
					Name:        "cancel",
					Description: "Cancel a scan and remove its partial data",
					Options: []*discordgo.ApplicationCommandOption{
						{
							Type:        discordgo.ApplicationCommandOptionInteger,
							Name:        "id",
							Description: "Job ID shown by /jobs list",
							Required:    true,
							MinValue:    &minimumJobID,
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
		if err := respond(session, event, "Choose either `/scan domain` or `/scan network`.", true); err != nil {
			log.Printf("validate /scan subcommand: %v", err)
		}
		return
	}
	switch options[0].Name {
	case "domain":
		b.handleDomainScan(session, event, options[0].Options)
	case "network":
		b.handleNetworkScan(session, event, options[0].Options)
	default:
		if err := respond(session, event, "Unknown `/scan` subcommand.", true); err != nil {
			log.Printf("reject unknown /scan subcommand: %v", err)
		}
	}
}

func (b *Bot) handleDomainScan(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	domain, ok := stringOption(options, "domain")
	if !ok {
		if err := respond(session, event, "The `domain` option is required.", true); err != nil {
			log.Printf("validate /scan domain: %v", err)
		}
		return
	}
	private := integerOption(options, "code") == privateDeliveryCode

	parent := b.context()
	queueID := b.scanQueue.Submit(parent, scanqueue.KindSubs, domain, func(ctx context.Context) int64 {
		return b.runDomainScan(ctx, session, event.ChannelID, event.Member.User.ID, domain, private)
	})

	destination := "this channel"
	if private {
		destination = "your DMs"
	}
	acknowledgement := fmt.Sprintf("Scan `#%d` queued for `%s`. The HTTPX results will be sent to %s when it finishes.", queueID, domain, destination)
	if err := respond(session, event, acknowledgement, private); err != nil {
		log.Printf("acknowledge /scan domain: %v", err)
		b.scanQueue.Delete(queueID)
		return
	}
}

func (b *Bot) runDomainScan(ctx context.Context, session *discordgo.Session, channelID, userID, domain string, private bool) int64 {
	deliveryChannelID := channelID
	if private {
		directMessage, dmErr := session.UserChannelCreate(userID)
		if dmErr != nil {
			log.Printf("open DM for /scan domain requester %s: %v", userID, dmErr)
			failure := fmt.Sprintf("<@%s> I couldn't open your DMs, so the private scan was not started.", userID)
			if _, sendErr := session.ChannelMessageSend(channelID, failure); sendErr != nil {
				log.Printf("report private /scan domain delivery failure: %v", sendErr)
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
			log.Printf("report /scan domain failure: %v", sendErr)
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
		log.Printf("publish /scan domain results for %q: %v", domain, err)
		fallback := fmt.Sprintf("<@%s> scan completed for `%s`, but Discord rejected the HTTPX attachment. The results remain saved in SQLite.", userID, result.Domain)
		if _, sendErr := session.ChannelMessageSend(deliveryChannelID, fallback); sendErr != nil {
			log.Printf("report /scan domain publish failure: %v", sendErr)
		}
	}
	return result.RunID
}

func (b *Bot) handleResults(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if !isAdministrator(event) {
		if err := respond(session, event, "Only server administrators can use `/results`.", true); err != nil {
			log.Printf("reject /results: %v", err)
		}
		return
	}
	options := event.ApplicationCommandData().Options
	if len(options) != 1 || options[0].Type != discordgo.ApplicationCommandOptionSubCommand {
		if err := respond(session, event, "Choose either `/results domain` or `/results roots`.", true); err != nil {
			log.Printf("validate /results subcommand: %v", err)
		}
		return
	}
	switch options[0].Name {
	case "domain":
		b.handleDomainResults(session, event, options[0].Options)
	case "roots":
		b.handleRootResults(session, event)
	default:
		if err := respond(session, event, "Unknown `/results` subcommand.", true); err != nil {
			log.Printf("reject unknown /results subcommand: %v", err)
		}
	}
}

func (b *Bot) handleDomainResults(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	query, ok := stringOption(options, "query")
	if !ok {
		if err := respond(session, event, "The `query` option is required.", true); err != nil {
			log.Printf("validate /results domain: %v", err)
		}
		return
	}
	view, hasView := stringOption(options, "view")
	if !hasView {
		view = "details"
	}
	if view != "details" && view != "urls" {
		if err := respond(session, event, "The `view` option must be `details` or `urls`.", true); err != nil {
			log.Printf("validate /results domain view: %v", err)
		}
		return
	}
	urlsOnly := view == "urls"
	format, hasFormat := stringOption(options, "format")
	if !hasFormat {
		format = "txt"
	}
	if format != "txt" && format != "xlsx" {
		if err := respond(session, event, "The `format` option must be `txt` or `xlsx`.", true); err != nil {
			log.Printf("validate /results domain format: %v", err)
		}
		return
	}

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /results domain response: %v", err)
		return
	}

	results, err := b.recon.Results(query)
	if err != nil {
		content := "Could not read previous scan results. Review the bot logs."
		if errors.Is(err, recon.ErrResultsNotFound) {
			content = fmt.Sprintf("No completed scan results found for `%s`.", query)
		} else {
			log.Printf("find /results domain for %q: %v", query, err)
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /results domain failure: %v", editErr)
		}
		return
	}

	outputs := make([]string, 0, len(results))
	for _, result := range results {
		outputs = append(outputs, result.HTTPXOutput)
	}
	content := fmt.Sprintf("Latest scan results for `%s`.", results[0].Domain)
	if len(results) > 1 || strings.Contains(query, "*") {
		content = fmt.Sprintf("Scan results matching `%s`.", query)
	}
	if format == "xlsx" {
		workbook, workbookErr := scanWorkbook(results, urlsOnly)
		if workbookErr != nil {
			log.Printf("build /results domain spreadsheet for %q: %v", query, workbookErr)
			failure := "Could not create the XLSX scan results. Review the bot logs."
			if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &failure}); editErr != nil {
				log.Printf("report /results domain spreadsheet failure: %v", editErr)
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
			log.Printf("send XLSX /results domain for %q: %v", query, editErr)
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
			log.Printf("send URL-only /results domain for %q: %v", query, editErr)
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
		log.Printf("send /results domain for %q: %v", query, err)
	}
}

func (b *Bot) handleRootResults(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /results roots response: %v", err)
		return
	}

	domains, err := b.recon.Domains()
	if err != nil {
		content := "Could not read the scan history. Review the bot logs."
		if errors.Is(err, recon.ErrResultsNotFound) {
			content = "No saved scan history was found."
		} else {
			log.Printf("list /results roots: %v", err)
		}
		if _, editErr := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content}); editErr != nil {
			log.Printf("report /results roots failure: %v", editErr)
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
		log.Printf("send /results roots: %v", err)
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
