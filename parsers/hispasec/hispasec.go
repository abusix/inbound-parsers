package hispasec

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
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subject = strings.ToLower(subject)

	event := events.NewEvent("hispasec")

	// Parse event date from email headers
	if dateSlice, ok := serializedEmail.Headers["date"]; ok && len(dateSlice) > 0 {
		if parsedDate := email.ParseDate(dateSlice[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Route to appropriate parser based on subject
	if strings.Contains(subject, "trojan") {
		return parseTrojan(body, subject, event)
	} else if strings.Contains(subject, "fraudulent") || strings.Contains(subject, "phishing") {
		return parseFraudulent(body, subject, event)
	} else if strings.Contains(subject, "unauthorized app") {
		return parseCopyright(body, subject, event)
	}

	return nil, fmt.Errorf("unknown subject type: %s", subject)
}

func parseFraudulent(body, subject string, event *events.Event) ([]*events.Event, error) {
	// Try to extract IP from subject
	if ip := common.ExtractOneIP(subject); ip != "" {
		event.IP = ip
	}

	// Extract URLs from URL block
	urlBlock := common.GetContinuousLinesUntilEmptyLine(body, "URL")
	for _, url := range urlBlock {
		url = strings.TrimSpace(url)
		if common.IsURL(url) {
			event.URL = url
			break
		}
	}

	// Get official URL
	officialURL := common.GetNonEmptyLineAfter(body, "official site")
	officialURL = strings.TrimSpace(officialURL)

	// Create phishing event type
	var phishing *events.Phishing
	if officialURL != "" && common.IsURL(officialURL) {
		phishing = events.NewPhishingWithOfficialURL(officialURL)
	} else {
		phishing = events.NewPhishing()
	}
	event.EventTypes = []events.EventType{phishing}

	// Add proof of fraudulent activities as evidence
	proof := common.GetNonEmptyLineAfter(body, "Proof of fraudulent activities")
	proof = strings.TrimSpace(proof)
	if proof != "" && common.IsURL(proof) {
		evidence := &events.Evidence{
			URLs: []events.UrlStore{
				{
					Description: "evidence",
					URL:         proof,
				},
			},
		}
		event.AddEventDetail(evidence)
	}

	return []*events.Event{event}, nil
}

func parseTrojan(body, subject string, event *events.Event) ([]*events.Event, error) {
	// Set malware event type
	event.EventTypes = []events.EventType{events.NewMalware("")}

	// Extract URLs from URL block
	// Replace "URLs:" with "URLs:\n" to ensure proper parsing
	bodyWithNewline := strings.Replace(body, "URLs:", "URLs:\n", -1)
	urlBlock := common.GetBlockAfterWithStop(bodyWithNewline, "URLs:", "")

	for _, url := range urlBlock {
		// Remove asterisks from URL
		urlCandidate := strings.Replace(url, "*", "", -1)
		urlCandidate = strings.TrimSpace(urlCandidate)
		if common.IsURL(urlCandidate) {
			event.URL = urlCandidate
			break
		}
	}

	// Extract IP from subject
	if ip := common.ExtractOneIP(subject); ip != "" {
		event.IP = ip
	}

	return []*events.Event{event}, nil
}

func parseCopyright(body, subject string, event *events.Event) ([]*events.Event, error) {
	// Extract URLs from URL block
	// Replace "URLs:" with "URLs:\n" to ensure proper parsing
	bodyWithNewline := strings.Replace(body, "URLs:", "URLs:\n", -1)
	urlBlock := common.GetBlockAfterWithStop(bodyWithNewline, "URLs:", "")

	for _, url := range urlBlock {
		// Remove asterisks from URL
		urlCandidate := strings.Replace(url, "*", "", -1)
		urlCandidate = strings.TrimSpace(urlCandidate)
		if common.IsURL(urlCandidate) {
			event.URL = urlCandidate
			break
		}
	}

	// Extract copyright owner from "in representation of" phrase
	copyrightOwner := common.FindStringWithoutMarkers(body, "in representation of", "")
	copyrightOwner = strings.TrimSpace(copyrightOwner)
	copyrightOwner = strings.TrimSuffix(copyrightOwner, ".")

	// Create copyright event type
	copyright := events.NewCopyright("", copyrightOwner, "")
	event.EventTypes = []events.EventType{copyright}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
