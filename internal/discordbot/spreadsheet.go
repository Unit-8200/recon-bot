package discordbot

import (
	"fmt"
	"strings"

	"github.com/Unit-8200/recon-bot/internal/recon"

	"github.com/xuri/excelize/v2"
)

const (
	httpxSpreadsheetFilename = "httpx_results.xlsx"
	urlsSpreadsheetFilename  = "urls.xlsx"
	xlsxContentType          = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

func scanWorkbook(results []recon.Result, urlsOnly bool) ([]byte, error) {
	workbook := excelize.NewFile()
	defer workbook.Close()

	sheet := "HTTP Probes"
	if urlsOnly {
		sheet = "URLs"
	}
	if err := workbook.SetSheetName("Sheet1", sheet); err != nil {
		return nil, fmt.Errorf("name spreadsheet sheet: %w", err)
	}
	headerStyle, err := workbook.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"1F4E78"}, Pattern: 1},
	})
	if err != nil {
		return nil, fmt.Errorf("create spreadsheet header style: %w", err)
	}
	stream, err := workbook.NewStreamWriter(sheet)
	if err != nil {
		return nil, fmt.Errorf("create spreadsheet writer: %w", err)
	}
	if err := stream.SetPanes(&excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"}); err != nil {
		return nil, fmt.Errorf("freeze spreadsheet header: %w", err)
	}

	if urlsOnly {
		if err := stream.SetColWidth(1, 1, 80); err != nil {
			return nil, fmt.Errorf("size URL spreadsheet column: %w", err)
		}
		if err := stream.SetRow("A1", []interface{}{excelize.Cell{StyleID: headerStyle, Value: "URL"}}); err != nil {
			return nil, fmt.Errorf("write URL spreadsheet header: %w", err)
		}
		outputs := make([]string, 0, len(results))
		for _, result := range results {
			outputs = append(outputs, result.HTTPXOutput)
		}
		for index, value := range recon.UniqueURLs(outputs...) {
			cell, cellErr := excelize.CoordinatesToCellName(1, index+2)
			if cellErr != nil {
				return nil, fmt.Errorf("create URL spreadsheet coordinate: %w", cellErr)
			}
			if err := stream.SetRow(cell, []interface{}{value}); err != nil {
				return nil, fmt.Errorf("write URL spreadsheet row: %w", err)
			}
		}
	} else {
		if err := writeHTTPProbeRows(stream, headerStyle, results); err != nil {
			return nil, err
		}
	}

	if err := stream.Flush(); err != nil {
		return nil, fmt.Errorf("finish spreadsheet: %w", err)
	}
	buffer, err := workbook.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("encode spreadsheet: %w", err)
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

func writeHTTPProbeRows(stream *excelize.StreamWriter, headerStyle int, results []recon.Result) error {
	headers := []string{
		"Root Domain", "Scan Started", "Probe Time", "URL", "Status Code", "Title",
		"Technologies", "Web Server", "IPs", "CDN", "CDN Name", "CDN Type",
		"Final URL", "Location", "Content Length", "Content Type", "Body Preview",
		"Input", "Scheme", "Host", "Port", "Error",
	}
	widths := []float64{28, 24, 24, 60, 12, 35, 40, 24, 28, 10, 18, 16, 60, 60, 16, 22, 60, 35, 10, 35, 10, 50}
	for index, width := range widths {
		if err := stream.SetColWidth(index+1, index+1, width); err != nil {
			return fmt.Errorf("size HTTP probe spreadsheet column: %w", err)
		}
	}
	header := make([]interface{}, len(headers))
	for index, value := range headers {
		header[index] = excelize.Cell{StyleID: headerStyle, Value: value}
	}
	if err := stream.SetRow("A1", header); err != nil {
		return fmt.Errorf("write HTTP probe spreadsheet header: %w", err)
	}

	rowNumber := 2
	for _, result := range results {
		for _, probe := range result.HTTPXResults {
			cell, err := excelize.CoordinatesToCellName(1, rowNumber)
			if err != nil {
				return fmt.Errorf("create HTTP probe spreadsheet coordinate: %w", err)
			}
			probeTime := ""
			if !probe.Timestamp.IsZero() {
				probeTime = probe.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z07:00")
			}
			row := []interface{}{
				result.Domain,
				result.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
				probeTime,
				probe.URL,
				probe.StatusCode,
				probe.Title,
				strings.Join(probe.Technologies, ", "),
				probe.WebServer,
				strings.Join(probe.IPs, ", "),
				probe.CDN,
				probe.CDNName,
				probe.CDNType,
				probe.FinalURL,
				probe.Location,
				probe.ContentLength,
				probe.ContentType,
				probe.BodyPreview,
				probe.Input,
				probe.Scheme,
				probe.Host,
				probe.Port,
				probe.Error,
			}
			if err := stream.SetRow(cell, row); err != nil {
				return fmt.Errorf("write HTTP probe spreadsheet row: %w", err)
			}
			rowNumber++
		}
	}
	return nil
}
