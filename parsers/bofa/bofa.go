package bofa

import (
	"fmt"
	"regexp"
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

	subject, _ := common.GetSubject(serializedEmail, false)

	// Determine which type of event to parse based on content
	if strings.Contains(body, "phishing") {
		return p.parsePhishing(body, serializedEmail)
	} else if strings.Contains(strings.ToLower(subject), "syn flood") {
		return p.parseDDoS(body, serializedEmail)
	} else {
		return p.parseExploit(body, serializedEmail)
	}
}

// parsePhishing parses phishing events from email body
func (p *Parser) parsePhishing(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	event := events.NewEvent("bofa")
	event.EventTypes = []events.EventType{events.NewPhishing()}

	// Extract sender email
	event.SenderEmail = strings.TrimSpace(common.FindStringWithoutMarkers(body, "Email account:", ""))

	// Extract IP address
	event.IP = common.FindStringWithoutMarkers(body, "Received:", "by")
	if event.IP == "" {
		// Fallback to subject
		if subject, ok := serializedEmail.Headers["subject"]; ok && len(subject) > 0 {
			event.IP = subject[0]
		}
	}

	// Extract event date
	if strings.Contains(body, "Date:") {
		eventDate := strings.TrimSpace(common.FindStringWithoutMarkers(body, "\nDate:", ""))
		if eventDate != "" {
			event.EventDate = email.ParseDate(eventDate)
		}
	} else {
		// Fallback to email date header
		if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
			event.EventDate = email.ParseDate(date[0])
		}
	}

	// Extract URL
	event.URL = common.GetNonEmptyLineAfter(body, "below phishing URL")

	return []*events.Event{event}, nil
}

// parseDDoS parses DDoS events from email body
func (p *Parser) parseDDoS(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var result []*events.Event
	ips := make(map[string]bool)

	// Extract block around "Targeted IP"
	block := common.GetBlockAround(body, "Targeted IP")
	if len(block) == 0 {
		return nil, fmt.Errorf("no DDoS data found in email")
	}

	// Convert multiple spaces to commas for CSV parsing
	var fields []string
	for _, line := range block {
		converted := regexp.MustCompile(`  +`).ReplaceAllString(line, ",")
		fields = append(fields, converted)
	}

	// Parse as CSV
	csvData := strings.Join(fields, "\n")
	rows, err := common.ParseCSVString(csvData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DDoS CSV: %w", err)
	}

	// Get event date from email headers
	var eventDate string
	if date, ok := serializedEmail.Headers["date"]; ok && len(date) > 0 {
		eventDate = date[0]
	}

	// Create an event for each unique IP
	for _, row := range rows {
		ip := row["Targeted IP"]
		if ip == "" || ips[ip] {
			continue
		}

		ips[ip] = true
		event := events.NewEvent("bofa")
		event.EventTypes = []events.EventType{events.NewDDoS()}
		event.IP = ip

		if eventDate != "" {
			event.EventDate = email.ParseDate(eventDate)
		}

		// Add attack type as event detail
		if attackType := row["Attack Type"]; attackType != "" {
			event.AddEventDetailSimple("attack_type", attackType)
		}

		// Add time range of attack
		if date := row["Date"]; date != "" {
			if time := row["Time"]; time != "" {
				event.AddEventDetailSimple("time_range_of_attack", date+" "+time)
			}
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid DDoS events parsed")
	}

	return result, nil
}

// parseExploit parses exploit events from HTML table in email body
func (p *Parser) parseExploit(body string, serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Extract CSV data from HTML table
	csvRows, err := common.ExtractHTMLTableAsCSV(body)
	if err != nil {
		return nil, fmt.Errorf("failed to extract HTML table: %w", err)
	}

	// Parse CSV rows
	csvData := strings.Join(csvRows, "\n")
	rows, err := common.ParseCSVString(csvData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse exploit CSV: %w", err)
	}

	var result []*events.Event

	for _, row := range rows {
		event := events.NewEvent("bofa")
		event.EventTypes = []events.EventType{events.NewExploit()}

		// Set event date
		if time := row["time"]; time != "" {
			event.EventDate = email.ParseDate(time)
		}

		// Set source IP
		event.IP = row["source"]

		// Set source port if numeric
		if srcPort := row["src port"]; srcPort != "" {
			if matched, _ := regexp.MatchString(`^\d+$`, srcPort); matched {
				if port, err := strconv.Atoi(srcPort); err == nil {
					event.Port = port
				}
			}
		}

		// Add target information
		targetIP := row["dst addr"]
		if targetIP == "None" {
			targetIP = ""
		}

		targetPort := row["dst port"]
		if targetPort == "None" {
			targetPort = ""
		}

		if targetIP != "" || targetPort != "" {
			event.AddEventDetail(&events.Target{
				IP:   targetIP,
				Port: targetPort,
			})
		}

		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid exploit events parsed")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
