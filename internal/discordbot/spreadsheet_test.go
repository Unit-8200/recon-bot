package discordbot

import (
	"bytes"
	"testing"
	"time"

	"github.com/Unit-8200/recon-bot/internal/modules/httpprobe"
	"github.com/Unit-8200/recon-bot/internal/recon"

	"github.com/xuri/excelize/v2"
)

func TestScanWorkbookContainsNormalizedHTTPProbeColumns(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	data, err := scanWorkbook([]recon.Result{{
		Domain:    "example.com",
		StartedAt: startedAt,
		HTTPXResults: []httpprobe.Result{{
			URL:          "https://www.example.com",
			StatusCode:   200,
			Title:        "Example",
			Technologies: []string{"Go", "nginx"},
			IPs:          []string{"192.0.2.1"},
		}},
	}}, false)
	if err != nil {
		t.Fatalf("scanWorkbook(): %v", err)
	}

	workbook, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("OpenReader(): %v", err)
	}
	defer workbook.Close()
	rows, err := workbook.GetRows("HTTP Probes")
	if err != nil {
		t.Fatalf("GetRows(): %v", err)
	}
	if len(rows) != 2 || rows[0][0] != "Root Domain" || rows[0][3] != "URL" {
		t.Fatalf("unexpected spreadsheet header: %#v", rows)
	}
	if rows[1][0] != "example.com" || rows[1][3] != "https://www.example.com" || rows[1][4] != "200" || rows[1][6] != "Go, nginx" {
		t.Fatalf("unexpected spreadsheet data row: %#v", rows[1])
	}
}

func TestScanWorkbookURLsOnlyIsUniqueAndSorted(t *testing.T) {
	t.Parallel()

	data, err := scanWorkbook([]recon.Result{
		{HTTPXOutput: "https://z.example [200]\nhttps://a.example [200]\n"},
		{HTTPXOutput: "https://a.example [301]\n"},
	}, true)
	if err != nil {
		t.Fatalf("scanWorkbook(): %v", err)
	}

	workbook, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("OpenReader(): %v", err)
	}
	defer workbook.Close()
	rows, err := workbook.GetRows("URLs")
	if err != nil {
		t.Fatalf("GetRows(): %v", err)
	}
	if len(rows) != 3 || rows[0][0] != "URL" || rows[1][0] != "https://a.example" || rows[2][0] != "https://z.example" {
		t.Fatalf("unexpected URL spreadsheet rows: %#v", rows)
	}
}
