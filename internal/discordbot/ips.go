package discordbot

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"discord-bot/internal/ipscan"

	"github.com/bwmarrin/discordgo"
)

const maxTargetsFileBytes = 8 << 20

func (b *Bot) handleIPs(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if event.Member == nil || event.Member.User == nil || event.Member.Permissions&discordgo.PermissionAdministrator == 0 {
		if err := respond(session, event, "Only server administrators can use `/ips`.", true); err != nil {
			log.Printf("reject /ips: %v", err)
		}
		return
	}

	data := event.ApplicationCommandData()
	inline, hasInline := stringOption(data.Options, "targets")
	attachment, hasAttachment := attachmentOption(data, "file")
	if hasInline == hasAttachment {
		if err := respond(session, event, "Provide exactly one of `targets` or `file`.", true); err != nil {
			log.Printf("validate /ips input options: %v", err)
		}
		return
	}
	ports, _ := stringOption(data.Options, "ports")

	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	}); err != nil {
		log.Printf("defer /ips response: %v", err)
		return
	}

	input := inline
	if hasAttachment {
		downloadCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		contents, err := downloadTargetsFile(downloadCtx, session, attachment)
		cancel()
		if err != nil {
			content := fmt.Sprintf("Could not read the target file: %v", err)
			_, _ = session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content})
			return
		}
		input = string(contents)
	}
	targets, err := ipscan.NormalizeTargets(input)
	if err != nil {
		content := fmt.Sprintf("Invalid target input: %v", err)
		_, _ = session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &content})
		return
	}

	acknowledgement := fmt.Sprintf("IP scan started with %d target entries.", len(targets))
	if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &acknowledgement}); err != nil {
		log.Printf("acknowledge /ips: %v", err)
		return
	}

	parent := b.runContext
	if parent == nil {
		parent = context.Background()
	}
	go b.runIPs(parent, session, event.ChannelID, event.Member.User.ID, targets, ports)
}

func (b *Bot) runIPs(ctx context.Context, session *discordgo.Session, channelID, userID string, targets []string, ports string) {
	result, err := b.ipScanner.Scan(ctx, targets, ports)
	if ctx.Err() != nil {
		log.Printf("IP scan stopped during bot shutdown: %v", ctx.Err())
		return
	}
	if err != nil {
		log.Printf("run /ips: %v", err)
		content := fmt.Sprintf("<@%s> IP scan failed. Review the bot logs.", userID)
		if result.Directory != "" {
			content = fmt.Sprintf("<@%s> IP scan stopped. Partial artifacts were saved in `%s`.", userID, result.Directory)
		}
		if _, sendErr := session.ChannelMessageSend(channelID, content); sendErr != nil {
			log.Printf("report /ips failure: %v", sendErr)
		}
		return
	}

	file, err := os.Open(result.ResultsFile)
	if err != nil {
		log.Printf("open /ips results: %v", err)
		if _, sendErr := session.ChannelMessageSend(channelID, fmt.Sprintf("<@%s> IP scan complete, but its saved result could not be attached.", userID)); sendErr != nil {
			log.Printf("report /ips attachment failure: %v", sendErr)
		}
		return
	}
	defer file.Close()
	if _, err := session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: fmt.Sprintf("<@%s> IP scan complete.", userID),
		Files: []*discordgo.File{
			{Name: ipscan.ResultsFilename, ContentType: "text/plain; charset=utf-8", Reader: file},
		},
	}); err != nil {
		log.Printf("publish /ips results: %v", err)
	}
}

func attachmentOption(data discordgo.ApplicationCommandInteractionData, name string) (*discordgo.MessageAttachment, bool) {
	for _, option := range data.Options {
		if option.Name != name || option.Type != discordgo.ApplicationCommandOptionAttachment {
			continue
		}
		id, ok := option.Value.(string)
		if !ok || data.Resolved == nil {
			return nil, false
		}
		attachment, ok := data.Resolved.Attachments[id]
		return attachment, ok && attachment != nil
	}
	return nil, false
}

func downloadTargetsFile(ctx context.Context, session *discordgo.Session, attachment *discordgo.MessageAttachment) ([]byte, error) {
	if attachment == nil {
		return nil, fmt.Errorf("attachment is required")
	}
	if attachment.Size > maxTargetsFileBytes {
		return nil, fmt.Errorf("file exceeds the 8 MiB limit")
	}
	parsedURL, err := url.Parse(attachment.URL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
		return nil, fmt.Errorf("attachment URL is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, attachment.URL, nil)
	if err != nil {
		return nil, err
	}
	client := session.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Discord returned HTTP %d", response.StatusCode)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxTargetsFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxTargetsFileBytes {
		return nil, fmt.Errorf("file exceeds the 8 MiB limit")
	}
	return contents, nil
}
