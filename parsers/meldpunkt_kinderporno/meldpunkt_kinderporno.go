package meldpunkt_kinderporno

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Check if subject contains "child sexual abuse"
	if !strings.Contains(strings.ToLower(subject), "child sexual abuse") {
		return nil, fmt.Errorf("unexpected subject format: %s", subject)
	}

	// Extract HTML table as CSV
	rows, err := common.ExtractHTMLTableAsCSV(body)
	if err != nil {
		return nil, fmt.Errorf("failed to extract HTML table: %w", err)
	}

	var result []*events.Event

	for _, row := range rows {
		// Split CSV row into columns
		parts := strings.Split(row, ",")
		if len(parts) < 3 {
			continue
		}

		url := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])
		dateStr := strings.TrimSpace(parts[2])

		// Skip empty rows
		if url == "" && ip == "" && dateStr == "" {
			continue
		}

		event := events.NewEvent("meldpunkt_kinderporno")
		event.EventTypes = []events.EventType{events.NewChildAbuse()}
		event.URL = url
		event.IP = ip
		event.EventDate = email.ParseDate(dateStr)

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
