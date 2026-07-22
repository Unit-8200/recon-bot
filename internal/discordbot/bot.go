// Package discordbot owns the Discord connection and interaction routing.
package discordbot

import (
	"context"
	"fmt"
	"log"

	"github.com/Unit-8200/recon-bot/internal/database"
	"github.com/Unit-8200/recon-bot/internal/modules/ipscan"
	"github.com/Unit-8200/recon-bot/internal/recon"
	"github.com/Unit-8200/recon-bot/internal/scanqueue"

	"github.com/bwmarrin/discordgo"
)

// ReconRunner is the complete passive-enumeration and HTTP-probing workflow.
type ReconRunner interface {
	Run(ctx context.Context, rootDomain string) (recon.Result, error)
	Results(query string) ([]recon.Result, error)
	Domains() ([]string, error)
}

// IPScanner runs certificate discovery against IP addresses and CIDR ranges.
type IPScanner interface {
	Scan(ctx context.Context, targets []string, ports string) (ipscan.Result, error)
}

// DataStore persists and retrieves values submitted through /storage add.
type DataStore interface {
	AddStoredItem(ctx context.Context, data, description string) (bool, error)
	StoredItems(ctx context.Context) ([]database.StoredItem, error)
}

// Bot manages a Discord session and its commands.
type Bot struct {
	session    *discordgo.Session
	guildID    string
	recon      ReconRunner
	ipScanner  IPScanner
	dataStore  DataStore
	scanQueue  *scanqueue.Manager
	runContext context.Context
}

// New constructs a Discord bot without opening its network connection.
func New(token, guildID string, reconRunner ReconRunner, ipScanner IPScanner, dataStore DataStore, queue *scanqueue.Manager) (*Bot, error) {
	if token == "" {
		return nil, fmt.Errorf("Discord token is required")
	}
	if reconRunner == nil {
		return nil, fmt.Errorf("recon runner is required")
	}
	if ipScanner == nil {
		return nil, fmt.Errorf("IP scanner is required")
	}
	if dataStore == nil {
		return nil, fmt.Errorf("data store is required")
	}
	if queue == nil {
		return nil, fmt.Errorf("scan queue is required")
	}

	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, fmt.Errorf("create Discord session: %w", err)
	}
	session.Identify.Intents = discordgo.IntentsGuilds

	bot := &Bot{
		session: session, guildID: guildID, recon: reconRunner, ipScanner: ipScanner,
		dataStore: dataStore, scanQueue: queue,
	}
	session.AddHandler(bot.readyHandler)
	session.AddHandler(bot.interactionHandler)

	return bot, nil
}

// Run connects, registers commands, and waits for cancellation.
func (b *Bot) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	b.runContext = ctx
	if err := b.session.Open(); err != nil {
		return fmt.Errorf("connect to Discord: %w", err)
	}
	defer b.session.Close()

	if _, err := b.session.ApplicationCommandBulkOverwrite(b.session.State.User.ID, b.guildID, commandDefinitions()); err != nil {
		return fmt.Errorf("register application commands: %w", err)
	}

	if b.guildID == "" {
		log.Println("registered global commands (they may take a while to appear)")
	} else {
		log.Printf("registered commands in development guild %s", b.guildID)
	}

	log.Println("bot is running; press Ctrl+C to stop")
	<-ctx.Done()
	log.Println("shutting down")
	return nil
}

func (b *Bot) readyHandler(_ *discordgo.Session, event *discordgo.Ready) {
	log.Printf("connected as %s", event.User.String())
}

func (b *Bot) interactionHandler(session *discordgo.Session, event *discordgo.InteractionCreate) {
	if event.Type != discordgo.InteractionApplicationCommand {
		return
	}

	switch event.ApplicationCommandData().Name {
	case "ping":
		b.handlePing(session, event)
	case "scan":
		b.handleScan(session, event)
	case "results":
		b.handleResults(session, event)
	case "storage":
		b.handleStorage(session, event)
	case "jobs":
		b.handleJobs(session, event)
	}
}
