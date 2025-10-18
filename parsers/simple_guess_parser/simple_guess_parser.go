package simple_guess_parser

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse analyzes emails to guess the abuse type based on subject and body content
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email components
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)

	// Convert to lowercase for case-insensitive matching
	subjectLower := strings.ToLower(subject)
	bodyLower := strings.ToLower(body)

	// Skip cron emails
	if strings.HasPrefix(subjectLower, "cron") {
		return nil, nil
	}

	// Check for rejection patterns
	if strings.Contains(subjectLower, "undelivered mail returned to sender") ||
		strings.Contains(subjectLower, "re:") {
		return nil, nil
	}

	// Require subject and date headers
	if serializedEmail.Headers == nil {
		return nil, nil
	}
	if _, hasSubject := serializedEmail.Headers["subject"]; !hasSubject {
		return nil, nil
	}
	if _, hasDate := serializedEmail.Headers["date"]; !hasDate {
		return nil, nil
	}

	// Create event
	event := events.NewEvent("simple_guess_parser")

	// Determine event type based on content
	var eventType events.EventType
	var username, password string

	// Check for SSH/SSHD login attacks
	if strings.Contains(subjectLower, "ssh") || strings.Contains(bodyLower, "sshd") {
		eventType = events.NewLoginAttack("", "")
		event.AddEventDetail(&events.Target{Service: "ssh"})
	} else if strings.Contains(subjectLower, "imap") || strings.Contains(subjectLower, "smtp") {
		// Check for IMAP/SMTP login attacks with credentials
		// Try to extract username and password from body
		if match := regexp.MustCompile(`(?i)login\s+"([^"]+)"\s+"([^"]+)"`).FindStringSubmatch(bodyLower); len(match) == 3 {
			username = match[1]
			password = match[2]
		}
		eventType = events.NewLoginAttack(username, password)
	} else if strings.Contains(subjectLower, "spam") {
		eventType = events.NewSpam()
	} else if containsAny(subjectLower, []string{"brute force", "abuse from", "fail2ban", "login attempts", "hacking attempt"}) ||
		containsAny(bodyLower, []string{"brute force", "abuse from", "fail2ban", "login attempts", "hacking attempt"}) {
		eventType = events.NewLoginAttack("", "")
	} else if (strings.Contains(subjectLower, "dmca") && !strings.Contains(subjectLower, "dmca@")) ||
		(strings.Contains(bodyLower, "dmca") && !strings.Contains(bodyLower, "dmca@")) {
		eventType = events.NewCopyright("", "", "")
	} else if strings.Contains(subjectLower, "abuse from") {
		eventType = events.NewLoginAttack("", "")
	} else if strings.Contains(subjectLower, "phis") || strings.Contains(bodyLower, "phishing") {
		eventType = events.NewPhishing()
	} else {
		// No matching pattern found
		return nil, nil
	}

	event.EventTypes = []events.EventType{eventType}

	// Parse event date from email date header
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		if parsedDate := email.ParseDate(dateHeaders[0]); parsedDate != nil {
			event.EventDate = parsedDate
		}
	}

	// Try to extract IP from subject first
	ip := common.IsIP(common.ExtractOneIP(subjectLower))
	if ip != "" {
		event.IP = ip
		return []*events.Event{event}, nil
	}

	// For spam events, allow events without IP (use header requirement)
	if _, isSpam := eventType.(*events.Spam); isSpam {
		// Add header requirement for spam events - require headers to be present
		event.AddRequirement("headers", events.NewOrRequirement([]interface{}{"headers"}))
		return []*events.Event{event}, nil
	}

	// Try to extract IP from body
	ip = common.IsIP(common.ExtractOneIP(bodyLower))
	if ip != "" {
		event.IP = ip
		return []*events.Event{event}, nil
	}

	// Try to extract URL from body (for copyright and phishing)
	_, isCopyright := eventType.(*events.Copyright)
	_, isPhishing := eventType.(*events.Phishing)
	if isCopyright || isPhishing {
		if url := extractURL(body); url != "" {
			event.URL = url
			// Validate event before returning
			if err := event.Validate(); err == nil {
				return []*events.Event{event}, nil
			}
		}
	}

	// No IP or URL found, cannot create valid event
	return nil, nil
}

// containsAny checks if text contains any of the given substrings
func containsAny(text string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(text, substr) {
			return true
		}
	}
	return false
}

// extractURL extracts a URL from text, looking for http/https patterns
// This is a simplified version without DNS checking
func extractURL(text string) string {
	// Look for http:// or https:// URLs
	urlPattern := regexp.MustCompile(`(?i)https?://[^\s<>"]+`)
	matches := urlPattern.FindAllString(text, -1)

	for _, url := range matches {
		// Clean up common trailing characters
		url = strings.TrimRight(url, ".,;:!?)")
		// Basic validation - must have a dot after the protocol
		if strings.Contains(url[8:], ".") || strings.Contains(url[7:], ".") {
			return url
		}
	}

	// Look for hxxp obfuscated URLs
	hxxpPattern := regexp.MustCompile(`(?i)hxxps?://[^\s<>"]+`)
	matches = hxxpPattern.FindAllString(text, -1)

	for _, url := range matches {
		// Clean up and de-obfuscate
		url = strings.TrimRight(url, ".,;:!?)")
		url = strings.Replace(url, "hxxp", "http", 1)
		if strings.Contains(url[8:], ".") || strings.Contains(url[7:], ".") {
			return url
		}
	}

	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 9999
}
