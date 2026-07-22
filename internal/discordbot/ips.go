package discordbot

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Unit-8200/recon-bot/internal/modules/ipscan"
	"github.com/Unit-8200/recon-bot/internal/scanqueue"

	"github.com/bwmarrin/discordgo"
)

const maxTargetsFileBytes = 8 << 20

func (b *Bot) handleNetworkScan(session *discordgo.Session, event *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	data := event.ApplicationCommandData()
	data.Options = options
	inline, hasInline := stringOption(options, "targets")
	attachment, hasAttachment := attachmentOption(data, "file")
	if hasInline == hasAttachment {
		if err := respond(session, event, "Provide exactly one of `targets` or `file`.", true); err != nil {
			log.Printf("validate /scan network input options: %v", err)
		}
		return
	}
	if err := session.InteractionRespond(event.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{},
	}); err != nil {
		log.Printf("defer /scan network response: %v", err)
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

	queueID := b.scanQueue.Submit(b.context(), scanqueue.KindIPs, fmt.Sprintf("%d target entries", len(targets)), func(ctx context.Context) int64 {
		return b.runNetworkScan(ctx, session, event.ChannelID, event.Member.User.ID, targets)
	})
	acknowledgement := fmt.Sprintf("Network scan `#%d` queued with %d target entries.", queueID, len(targets))
	if _, err := session.InteractionResponseEdit(event.Interaction, &discordgo.WebhookEdit{Content: &acknowledgement}); err != nil {
		log.Printf("acknowledge /scan network: %v", err)
		b.scanQueue.Delete(queueID)
		return
	}
}

func (b *Bot) runNetworkScan(ctx context.Context, session *discordgo.Session, channelID, userID string, targets []string) int64 {
	result, err := b.ipScanner.Scan(ctx, targets, "")
	if ctx.Err() != nil {
		log.Printf("network scan cancelled: %v", ctx.Err())
		return result.RunID
	}
	if err != nil {
		log.Printf("run /scan network: %v", err)
		content := fmt.Sprintf("<@%s> network scan failed. Review the bot logs.", userID)
		if result.RunID != 0 {
			content = fmt.Sprintf("<@%s> network scan stopped. Partial scan data was saved in SQLite.", userID)
		}
		if _, sendErr := session.ChannelMessageSend(channelID, content); sendErr != nil {
			log.Printf("report /scan network failure: %v", sendErr)
		}
		return result.RunID
	}

	if _, err := session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: fmt.Sprintf("<@%s> network scan complete.", userID),
		Files: []*discordgo.File{
			{Name: ipscan.ResultsFilename, ContentType: "text/plain; charset=utf-8", Reader: strings.NewReader(result.Output)},
		},
	}); err != nil {
		log.Printf("publish /scan network results: %v", err)
	}
	return result.RunID
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
