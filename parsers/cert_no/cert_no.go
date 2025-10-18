package cert_no

import (
	"strconv"
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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Try to extract CSV data from body
	var csvData string
	bodyLower := strings.ToLower(body)
	bodyLower = strings.ReplaceAll(bodyLower, `"`, "")

	// First try to get block after "--- report ---"
	block := common.GetBlockAfterWithStop(bodyLower, "--- report ---", "")
	if len(block) > 0 {
		csvData = strings.Join(block, "\n")
	} else if len(serializedEmail.Parts) >= 2 {
		// Fallback to second part's body
		if partBody, ok := serializedEmail.Parts[1].Body.(string); ok {
			csvData = strings.ReplaceAll(partBody, `"`, "")
		} else if partBodyBytes, ok := serializedEmail.Parts[1].Body.([]byte); ok {
			csvData = strings.ReplaceAll(string(partBodyBytes), `"`, "")
		} else {
			return nil, common.NewParserError("no event created")
		}
	} else {
		return nil, common.NewParserError("no event created")
	}

	// Parse CSV data
	rows, err := common.ParseCSVString(csvData)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, common.NewParserError("no event created")
	}

	var result []*events.Event
	for _, row := range rows {
		event := events.NewEvent("cert_no")

		// Set event date
		if timestamp := row["timestamp"]; timestamp != "" {
			event.EventDate = email.ParseDate(timestamp)
		}

		// Set source IP
		event.IP = row["src_ip"]

		// Set source port
		if srcPort := row["src_port"]; srcPort != "" {
			if port, err := strconv.Atoi(srcPort); err == nil {
				event.Port = port
			}
		}

		// Add ASN
		if srcASN := row["src_asn"]; srcASN != "" {
			event.AddEventDetail(&events.ASN{
				ASN: srcASN,
			})
		}

		// Add target
		targetIP := row["dst_ip"]
		targetPort := row["dst_port"]
		if targetIP != "" || targetPort != "" {
			event.AddEventDetail(&events.Target{
				IP:   targetIP,
				Port: targetPort,
			})
		}

		// Set event type based on category
		category := strings.ToLower(row["category"])
		if strings.Contains(category, "drone") || strings.Contains(category, "bot") {
			event.EventTypes = []events.EventType{events.NewBot("")}
		} else {
			return nil, common.NewNewTypeError(row["category"])
		}

		result = append(result, event)
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
