package discordbot

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"
)

func TestAttachmentOptionResolvesUploadedFile(t *testing.T) {
	t.Parallel()

	want := &discordgo.MessageAttachment{ID: "attachment-id", Filename: "targets.txt"}
	data := discordgo.ApplicationCommandInteractionData{
		Options: []*discordgo.ApplicationCommandInteractionDataOption{
			{Name: "file", Type: discordgo.ApplicationCommandOptionAttachment, Value: "attachment-id"},
		},
		Resolved: &discordgo.ApplicationCommandInteractionDataResolved{
			Attachments: map[string]*discordgo.MessageAttachment{"attachment-id": want},
		},
	}

	got, ok := attachmentOption(data, "file")
	if !ok || got != want {
		t.Fatalf("attachmentOption() = %#v, %t", got, ok)
	}
}

func TestDownloadTargetsFile(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("192.0.2.1\n198.51.100.0/24\n")),
			Request:    request,
		}, nil
	})}
	session := &discordgo.Session{Client: client}
	attachment := &discordgo.MessageAttachment{URL: "https://cdn.discord.example/targets.txt", Size: 30}
	got, err := downloadTargetsFile(context.Background(), session, attachment)
	if err != nil {
		t.Fatalf("downloadTargetsFile(): %v", err)
	}
	if string(got) != "192.0.2.1\n198.51.100.0/24\n" {
		t.Fatalf("downloadTargetsFile() = %q", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
