package discordbot

import (
	"strings"
	"testing"

	"github.com/Unit-8200/recon-bot/internal/scanqueue"
)

func TestRenderQueue(t *testing.T) {
	t.Parallel()

	output := renderQueue([]scanqueue.Job{
		{ID: 7, Status: scanqueue.StatusRunning, Kind: scanqueue.KindSubs, Target: "example.com"},
		{ID: 8, Status: scanqueue.StatusQueued, Kind: scanqueue.KindIPs, Target: "20 target entries"},
	})
	for _, value := range []string{"#7", "running", "subs", "example.com", "#8", "queued", "ips", "20 target entries"} {
		if !strings.Contains(output, value) {
			t.Fatalf("renderQueue() = %q, missing %q", output, value)
		}
	}
}
