package web

import (
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser handles emails from redhead874@web.de
type Parser struct{}

// NewParser creates a new web parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses copyright infringement reports from web.de
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}

	subjectLower := strings.ToLower(subject)

	// Check if this is a copyright infringement email
	if !strings.Contains(subjectLower, "copyright infringement") && !strings.Contains(subjectLower, "copyright infringment") {
		return nil, fmt.Errorf("unrecognized subject format: %s", subject)
	}

	return p.parseCopyright(serializedEmail, subjectLower)
}

// parseCopyright parses copyright infringement reports
func (p *Parser) parseCopyright(serializedEmail *email.SerializedEmail, subject string) ([]*events.Event, error) {
	bodyHTML, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get body: %w", err)
	}

	// Parse HTML and extract text
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyHTML))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Get text content with newline separators
	body := doc.Text()
	// Remove non-breaking spaces and convert to lowercase
	body = strings.ReplaceAll(body, "\u00a0", "")
	body = strings.ToLower(body)

	// Find the start index based on subject content
	var startIndex int
	if strings.Contains(subject, "infringment") {
		idx := strings.Index(body, "pictures")
		if idx == -1 {
			return nil, fmt.Errorf("could not find 'pictures' marker in email body")
		}
		startIndex = idx + len("pictures")
	} else {
		// Look for 'upload-filter' or 'laptop'
		found := false
		for _, marker := range []string{"upload-filter", "laptop"} {
			if idx := strings.Index(body, marker); idx != -1 {
				startIndex = idx + len(marker)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("could not find 'upload-filter' or 'laptop' marker in email body")
		}
	}

	// Find end index
	endIndex := strings.Index(body, "i swear,")
	if endIndex == -1 {
		return nil, fmt.Errorf("could not find 'i swear,' marker in email body")
	}

	// Extract URLs from the section between markers
	urlsPart := body[startIndex:endIndex]
	lines := strings.Split(urlsPart, "\n")

	var result []*events.Event

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines, single dots, and lines without http
		if line == "" || line == "." || !strings.Contains(line, "http") {
			continue
		}

		// Create event for each URL
		event := events.NewEvent("web")
		event.EventTypes = []events.EventType{
			events.NewCopyright(line, "", ""),
		}

		// Set event date from email headers
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}

		event.URL = line
		result = append(result, event)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no URLs found in email body")
	}

	return result, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
