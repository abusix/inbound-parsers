package shadowserver_digest

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/parsers/shadowserver"
)

var (
	urlPatternAlternative = regexp.MustCompile(`https?://\S*dl\.shadowserver\.org\S*`)
	urlPatternURLDefense  = regexp.MustCompile(`(https://urldefense\.com/v\d/__)?https?://dl\.shadowserver\.org/\S*`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse implements the shadowserver_digest parser logic
// Python: def parse(serialized_email):
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var allEvents []*events.Event
	shadowParser := shadowserver.NewParser()

	// Iterate through email parts looking for multipart/digest
	for _, part := range serializedEmail.Parts {
		contentType := getContentType(part)

		// Check if this is a multipart/digest part
		if strings.Contains(contentType, "multipart/digest") {
			// Check if part has nested parts
			if len(part.Parts) > 0 {
				// Process each sub-part as a fake email
				for _, subPart := range part.Parts {
					fakeMail := createFakeMail(subPart, serializedEmail.Identifier)

					// Parse the fake mail using shadowserver parser
					subEvents, err := shadowParser.Parse(fakeMail)
					if err != nil {
						// Log error but continue processing other parts
						continue
					}
					allEvents = append(allEvents, subEvents...)
				}
			} else {
				// No nested parts, look for download URL
				url := getDownloadURL(getPartBody(part))
				if url != "" {
					// Get subject from part headers for event type determination
					subject := getPartSubject(part)

					// TODO: Implement parse_downloadable functionality
					// For now, create a placeholder event
					event := events.NewEvent("shadowserver_digest")
					event.EventTypes = []events.EventType{events.NewUnknown()}
					event.AddEventDetailSimple("url", url)
					event.AddEventDetailSimple("subject", subject)
					allEvents = append(allEvents, event)
				}
			}
		}
	}

	if len(allEvents) == 0 {
		return nil, common.NewParserError("No event created")
	}

	return allEvents, nil
}

// getContentType extracts the content-type from part headers
func getContentType(part email.EmailPart) string {
	if part.Headers != nil {
		if ct, ok := part.Headers["content-type"]; ok && len(ct) > 0 {
			return strings.ToLower(ct[0])
		}
	}
	if part.ContentType != "" {
		return strings.ToLower(part.ContentType)
	}
	return ""
}

// getPartBody extracts the body from an email part
func getPartBody(part email.EmailPart) string {
	switch body := part.Body.(type) {
	case string:
		return body
	case []byte:
		return string(body)
	default:
		return ""
	}
}

// getPartSubject extracts subject from part headers
func getPartSubject(part email.EmailPart) string {
	if part.Headers != nil {
		if subj, ok := part.Headers["subject"]; ok && len(subj) > 0 {
			return subj[0]
		}
	}
	return ""
}

// getDownloadURL extracts shadowserver download URL from email body
// Python: def _get_download_url(body: str) -> Optional[str]:
func getDownloadURL(body string) string {
	if body == "" || !strings.Contains(body, "dl.shadowserver.org") {
		return ""
	}

	// Try URL defense pattern first
	if match := urlPatternURLDefense.FindString(body); match != "" {
		return match
	}

	// Try alternative pattern
	if match := urlPatternAlternative.FindString(body); match != "" {
		return match
	}

	return ""
}

// createFakeMail creates a SerializedEmail from an email part
// Python: fake_mail = sub_part['parts'][0] or fake_mail = sub_part
//         fake_mail['identifier'] = serialized_email['identifier']
func createFakeMail(part email.EmailPart, identifier string) *email.SerializedEmail {
	fakeMail := &email.SerializedEmail{
		Identifier: identifier,
		Headers:    make(map[string][]string),
		Parts:      []email.EmailPart{},
	}

	// If part has exactly one sub-part, use it
	if len(part.Parts) == 1 {
		fakeMail.Body = part.Parts[0].Body
		fakeMail.Headers = part.Parts[0].Headers
		if len(part.Parts[0].Parts) > 0 {
			fakeMail.Parts = part.Parts[0].Parts
		}
	} else if len(part.Parts) > 1 {
		// Multiple parts, use the part itself
		fakeMail.Body = part.Body
		fakeMail.Headers = part.Headers
		fakeMail.Parts = part.Parts
	} else {
		// No sub-parts, use the part directly
		fakeMail.Body = part.Body
		fakeMail.Headers = part.Headers
	}

	return fakeMail
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
