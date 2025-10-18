// Package zero_spam implements the 0spam parser
package zero_spam

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the zero_spam parser
type Parser struct{}

var (
	ipDatePattern = regexp.MustCompile(`\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\) was the source of spam on \((.*)\)`)
)

// NewParser creates a new zero_spam parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Match checks if this parser should handle the email
func (p *Parser) Match(fromAddr string) bool {
	return fromAddr != "" && strings.Contains(fromAddr, "@0spam")
}

// Parse parses emails from 0spam
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Extract IP and date using regex
	matches := ipDatePattern.FindStringSubmatch(body)
	if len(matches) < 3 {
		return nil, common.NewParserError("ip & date regex failed to match")
	}

	ip := matches[1]
	dateStr := matches[2]

	event := events.NewEvent("zero_spam")
	event.EventTypes = []events.EventType{events.NewSpam()}
	event.IP = ip

	// Parse the date string
	eventDate := email.ParseDate(dateStr)
	event.EventDate = eventDate

	return []*events.Event{event}, nil
}

// GetName returns the parser name
func (p *Parser) GetName() string {
	return "zero_spam"
}

// GetDescription returns the parser description
func (p *Parser) GetDescription() string {
	return "Parser for 0spam abuse reports"
}

// ValidateMatchCriteria validates that the parser's match criteria are met
func (p *Parser) ValidateMatchCriteria(serializedEmail *email.SerializedEmail) error {
	fromAddrs, ok := serializedEmail.Headers["from"]
	if !ok || len(fromAddrs) == 0 {
		return fmt.Errorf("no from address found")
	}

	fromAddr := strings.ToLower(fromAddrs[0])
	if !p.Match(fromAddr) {
		return fmt.Errorf("from address %s does not match zero_spam criteria", fromAddr)
	}

	return nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
