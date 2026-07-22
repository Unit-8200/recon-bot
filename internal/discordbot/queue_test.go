package discordbot

import (
	"strings"
	"testing"

	"github.com/Unit-8200/recon-bot/internal/scanqueue"
)

func TestRenderJobs(t *testing.T) {
	t.Parallel()

	output := renderJobs([]scanqueue.Job{
		{ID: 7, Status: scanqueue.StatusRunning, Kind: scanqueue.KindSubs, Target: "example.com"},
		{ID: 8, Status: scanqueue.StatusQueued, Kind: scanqueue.KindIPs, Target: "20 target entries"},
	})
	for _, value := range []string{"#7", "running", "domain", "example.com", "#8", "queued", "network", "20 target entries"} {
		if !strings.Contains(output, value) {
			t.Fatalf("renderJobs() = %q, missing %q", output, value)
		}
	}
}
