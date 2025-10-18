package ukrbit

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
	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	// Check if subject contains 'spam'
	if !strings.Contains(strings.ToLower(subject), "spam") {
		return nil, common.NewNewTypeError(subject)
	}

	// Find attached evidence
	var evidence *email.EmailPart
	for i := range serializedEmail.Parts {
		part := &serializedEmail.Parts[i]
		if part.Headers != nil {
			if disposition, ok := part.Headers["content-disposition"]; ok {
				for _, disp := range disposition {
					if strings.Contains(strings.ToLower(disp), "attachment") {
						evidence = part
						break
					}
				}
			}
		}
		if evidence != nil {
			break
		}
	}

	if evidence == nil {
		return nil, common.NewParserError("Could not find expected evidence attachment")
	}

	event := events.NewEvent("ukrbit")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Try to extract IP from x-php-script header first
	if evidence.Headers != nil {
		if xPhpScript, ok := evidence.Headers["x-php-script"]; ok && len(xPhpScript) > 0 {
			event.IP = common.ExtractOneIP(xPhpScript[0])
			// Get date from evidence headers
			if dateHeaders, ok := evidence.Headers["date"]; ok && len(dateHeaders) > 0 {
				event.EventDate = email.ParseDate(dateHeaders[0])
			}
		} else {
			// Extract from received headers
			if receivedHeaders, ok := evidence.Headers["received"]; ok && len(receivedHeaders) > 0 {
				for _, receivedEntry := range receivedHeaders {
					ip := common.ExtractOneIP(receivedEntry)
					if ip != "" {
						event.IP = ip

						// Try to get date from this received header
						receivedHeader := email.NewReceivedHeader([]string{receivedEntry})
						if parsedDate := receivedHeader.ReceivedDate(0); parsedDate != nil {
							event.EventDate = parsedDate
						} else {
							// Fallback to date header
							if dateHeaders, ok := evidence.Headers["date"]; ok && len(dateHeaders) > 0 {
								event.EventDate = email.ParseDate(dateHeaders[0])
							}
						}
						break
					}
				}
			}
		}

		// Extract envelope-from from first received header if available
		if receivedHeaders, ok := evidence.Headers["received"]; ok && len(receivedHeaders) > 0 {
			if strings.Contains(receivedHeaders[0], "envelope-from") {
				envelopeFromStr := common.FindStringWithoutMarkers(receivedHeaders[0], "envelope-from", "")
				envelopeFrom := common.ExtractOneEmail(envelopeFromStr)
				if envelopeFrom != "" {
					event.AddEventDetail(&events.Email{FromAddress: envelopeFrom})
				}
			}
		}
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
