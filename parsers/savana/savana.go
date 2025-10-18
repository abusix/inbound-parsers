package savana

import (
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

	// Get block after "LOG" marker
	lines := common.GetBlockAfterWithStop(body, "LOG", "")
	if len(lines) == 0 {
		return nil, common.NewParserError("no data found after LOG marker")
	}

	// Group lines into blocks (each block starts with a line beginning with an IP)
	blocks := groupData(lines)

	var eventsList []*events.Event
	for _, block := range blocks {
		if len(block) < 2 {
			continue
		}

		event := events.NewEvent("savana")
		event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}

		// First line starts with IP address
		fields := strings.Fields(block[0])
		if len(fields) > 0 {
			ip := common.IsIP(fields[0])
			if ip != "" {
				event.IP = ip
			}
		}

		// Second line contains event date in brackets and target URL
		if len(block) > 1 {
			// Extract date from between [ and ]
			dateStr := common.FindStringWithoutMarkers(block[1], "[", "]")
			if dateStr != "" {
				eventDate := email.ParseDate(dateStr)
				event.EventDate = eventDate
			}

			// First field in second line is the target URL
			fields := strings.Fields(block[1])
			if len(fields) > 0 {
				event.AddEventDetail(&events.Target{
					URL: fields[0],
				})
			}
		}

		eventsList = append(eventsList, event)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events created")
	}

	return eventsList, nil
}

// groupData groups lines into blocks where each block starts with a line beginning with an IP
func groupData(lines []string) [][]string {
	var blocks [][]string
	var currentBlock []string

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && common.IsIP(fields[0]) != "" {
			// Start of a new block
			if len(currentBlock) > 0 {
				blocks = append(blocks, currentBlock)
			}
			currentBlock = []string{line}
		} else if len(currentBlock) > 0 {
			// Continuation of current block
			currentBlock = append(currentBlock, line)
		}
	}

	// Don't forget the last block
	if len(currentBlock) > 0 {
		blocks = append(blocks, currentBlock)
	}

	return blocks
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
