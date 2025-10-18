package stackpath

import (
	"strings"

	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/events"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// getPartWithAttachment finds the email part with message/rfc822 content type
func getPartWithAttachment(serializedEmail *email.SerializedEmail) *email.EmailPart {
	for i := range serializedEmail.Parts {
		part := &serializedEmail.Parts[i]
		if part.Headers != nil {
			if contentTypes, ok := part.Headers["content-type"]; ok {
				for _, ct := range contentTypes {
					if strings.Contains(strings.ToLower(ct), "message/rfc822") {
						return part
					}
				}
			}
		}
		// Also check the ContentType field
		if strings.Contains(strings.ToLower(part.ContentType), "message/rfc822") {
			return part
		}
	}
	return nil
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get From address
	from, _ := common.GetFrom(serializedEmail, false)

	// Only process emails from gary.kline@stackpath.com
	if from != "gary.kline@stackpath.com" {
		return nil, common.NewParserError("not a stackpath forwarded email")
	}

	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	// Check for message/rfc822 attachment
	if part := getPartWithAttachment(serializedEmail); part != nil {
		// Check if the attached email is also from stackpath (forwarding loop)
		if part.Headers != nil {
			if fromHeaders, ok := part.Headers["from"]; ok && len(fromHeaders) > 0 {
				if strings.Contains(strings.ToLower(fromHeaders[0]), "stackpath") {
					// Reject: forwarding loop detected (stackpath.rejected.0.eml)
					return nil, common.NewParserError("stackpath forwarding loop detected")
				}
			}
		}
		// If we have a valid attachment, this should be rewritten
		// In the Go architecture, we can't rewrite emails, so we return an error
		// to signal that this email needs special handling
		return nil, common.NewParserError("stackpath email with rfc822 attachment requires rewrite")
	}

	// No attachment - check body for forwarding indicators
	if !strings.Contains(bodyLower, "forwarding") && !strings.Contains(bodyLower, "for handling") {
		// Reject: simple forward without proper indicators (stackpath.rejected.1.eml)
		return nil, common.NewParserError("stackpath email without forwarding indicators")
	}

	// Check if body contains email headers
	if strings.Contains(bodyLower, "from:") {
		newFromAddress := common.FindStringWithoutMarkers(bodyLower, "from:", "\n")
		if strings.Contains(newFromAddress, "stackpath") {
			// Reject: forwarded email is from stackpath (stackpath.rejected.3.eml)
			return nil, common.NewParserError("stackpath forwarded email from stackpath address")
		}
	}

	// Check if body contains full email headers (From:/Sent:/To:/Subject:)
	if strings.Contains(bodyLower, "from:") &&
		strings.Contains(bodyLower, "sent:") &&
		strings.Contains(bodyLower, "to:") &&
		strings.Contains(bodyLower, "subject:") {
		// This email should be rewritten - extract headers from body
		// In the Go architecture, we can't rewrite emails, so we return an error
		return nil, common.NewParserError("stackpath email with headers in body requires rewrite")
	}

	// If we get here, the email matches the pattern but doesn't fit any known case
	return nil, common.NewParserError("stackpath email format not recognized")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
