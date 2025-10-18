package simple_url_report

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

// ParserSettings defines extraction methods for each sender
type ParserSettings struct {
	DateMethod string
	URLMethod  string
	IPMethod   string
}

// Settings maps from email addresses to their parser configuration
var Settings = map[string]ParserSettings{
	"auscert@auscert.org.au": {
		DateMethod: "date_headers",
		URLMethod:  "url_body_wrapper",
		IPMethod:   "ip_subject",
	},
	"jpinillos@easysol.net": {
		DateMethod: "date_headers",
		URLMethod:  "url_parts_0_body_raw_http_nl",
		IPMethod:   "ip_subject",
	},
	"portal@axur.com": {
		DateMethod: "date_headers",
		URLMethod:  "url_parts_0_body_raw_http_nl",
		IPMethod:   "ip_parts_0_body_raw",
	},
	"isaac@godaddy.com": {
		DateMethod: "date_headers",
		URLMethod:  "url_body_hxxp_nl",
		IPMethod:   "ip_body_ip_nl",
	},
	"ir@brandprotect.com": {
		DateMethod: "date_headers",
		URLMethod:  "url_parts_0_body_raw_hxxp_nl",
		IPMethod:   "ip_subject",
	},
	"alert@internetidentity.com": {
		DateMethod: "date_headers",
		URLMethod:  "url_body_wrapper",
		IPMethod:   "ip_subject",
	},
	"ncert@cert.hr": {
		DateMethod: "date_headers",
		URLMethod:  "url_body_wrapper",
		IPMethod:   "ip_subject",
	},
	"ftsteam@paypal.com": {
		DateMethod: "date_headers",
		URLMethod:  "url_body_wrapper",
		IPMethod:   "ip_subject",
	},
	"cert-soc@lexsi.com": {
		DateMethod: "date_headers",
		URLMethod:  "url_body_wrapper",
		IPMethod:   "ip_body",
	},
}

func NewParser() *Parser {
	return &Parser{}
}

// cleanHTMLAndSpecialCharacters removes HTML and special characters from URL
func cleanHTMLAndSpecialCharacters(protocol, url string) string {
	url = rightOrLeft(url, "/>", protocol)
	url = rightOrLeft(url, "<br", protocol)
	url = rightOrLeft(url, "\t", protocol)
	url = rightOrLeft(url, "\n", protocol)
	return url
}

// rightOrLeft splits URL based on search string position relative to protocol
func rightOrLeft(url, searchString, protocol string) string {
	pos := strings.Index(url, protocol)
	location := strings.Index(url, searchString)
	if location != -1 {
		if pos < location {
			// Protocol comes before search string - take left part
			url = strings.Split(url, searchString)[0]
		} else {
			// Protocol comes after search string - take right part
			parts := strings.Split(url, searchString)
			if len(parts) > 0 {
				url = parts[len(parts)-1]
			}
		}
	}
	return url
}

// tryFindHxxp attempts to find URL with hxxp or http protocol
func tryFindHxxp(body string) (string, string) {
	// Try hxxp first (case insensitive)
	if url := common.FindString(strings.ToLower(body), "hxxp", "\n"); url != "" {
		return "hxxp", url
	}
	// Try http
	if url := common.FindString(body, "http", "\n"); url != "" {
		return "http", url
	}
	return "", ""
}

// urlBodyHTTPNL extracts URL from various body fields
func urlBodyHTTPNL(serializedEmail *email.SerializedEmail) (string, string) {
	// Try body first
	if body, err := common.GetBody(serializedEmail, false); err == nil && body != "" {
		if protocol, url := tryFindHxxp(body); url != "" {
			return protocol, url
		}
	}

	// Try parts
	for _, part := range serializedEmail.Parts {
		if partBody, ok := part.Body.(string); ok {
			if protocol, url := tryFindHxxp(partBody); url != "" {
				return protocol, url
			}
		}
	}

	return "", ""
}

// Date extraction methods
func dateHeaders(serializedEmail *email.SerializedEmail) *string {
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		return &dateHeader[0]
	}
	return nil
}

// URL extraction methods
func urlBodyWrapper(serializedEmail *email.SerializedEmail) string {
	protocol, url := urlBodyHTTPNL(serializedEmail)
	if url != "" {
		return cleanHTMLAndSpecialCharacters(protocol, url)
	}
	return ""
}

func urlParts0BodyRawHTTPNL(serializedEmail *email.SerializedEmail) string {
	if len(serializedEmail.Parts) > 0 {
		if partBody, ok := serializedEmail.Parts[0].Body.(string); ok {
			return common.FindString(partBody, "http", "\n")
		}
	}
	return ""
}

func urlBodyHxxpNL(serializedEmail *email.SerializedEmail) string {
	body, _ := common.GetBody(serializedEmail, false)
	return common.FindString(body, "hXXp", "\n")
}

func urlParts0BodyRawHxxpNL(serializedEmail *email.SerializedEmail) string {
	if len(serializedEmail.Parts) > 0 {
		if partBody, ok := serializedEmail.Parts[0].Body.(string); ok {
			return common.FindString(partBody, "hxxp", "\n")
		}
	}
	return ""
}

// IP extraction methods
func ipSubject(serializedEmail *email.SerializedEmail) string {
	subject, _ := common.GetSubject(serializedEmail, false)
	return common.ExtractOneIP(subject)
}

func ipBodyIPNL(serializedEmail *email.SerializedEmail) string {
	body, _ := common.GetBody(serializedEmail, false)
	ipStr := common.FindString(body, "IP:", "\n")
	if ipStr != "" {
		ipStr = strings.TrimPrefix(ipStr, "IP:")
		ipStr = strings.TrimSpace(ipStr)
		return common.IsIP(ipStr)
	}
	return ""
}

func ipBody(serializedEmail *email.SerializedEmail) string {
	// Try body
	body, _ := common.GetBody(serializedEmail, false)
	ip := common.ExtractOneIP(body)
	if ip != "" {
		return ip
	}

	// Try parts
	for _, part := range serializedEmail.Parts {
		if partBody, ok := part.Body.(string); ok {
			ip = common.ExtractOneIP(partBody)
			if ip != "" {
				return ip
			}
		}
	}

	return ""
}

func ipParts0BodyRaw(serializedEmail *email.SerializedEmail) string {
	if len(serializedEmail.Parts) > 0 {
		if partBody, ok := serializedEmail.Parts[0].Body.(string); ok {
			ipStr := common.FindString(partBody, "IP:", "\n")
			if ipStr != "" {
				ipStr = strings.TrimPrefix(ipStr, "IP:")
				ipStr = strings.TrimSpace(ipStr)
				return common.IsIP(ipStr)
			}
		}
	}
	return ""
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Extract from address
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil || fromAddr == "" {
		return nil, common.NewParserError("no from address found")
	}

	// Check if sender is in settings
	settings, ok := Settings[strings.ToLower(fromAddr)]
	if !ok {
		return nil, common.NewParserError("unknown sender: " + fromAddr)
	}

	// Create event
	event := events.NewEvent("simple_url_report")

	// Extract date
	if settings.DateMethod == "date_headers" {
		if dateStr := dateHeaders(serializedEmail); dateStr != nil {
			if parsedDate := email.ParseDate(*dateStr); parsedDate != nil {
				event.EventDate = parsedDate
			}
		}
	}

	// Extract IP using configured method
	var ip string
	switch settings.IPMethod {
	case "ip_subject":
		ip = ipSubject(serializedEmail)
	case "ip_body_ip_nl":
		ip = ipBodyIPNL(serializedEmail)
	case "ip_body":
		ip = ipBody(serializedEmail)
	case "ip_parts_0_body_raw":
		ip = ipParts0BodyRaw(serializedEmail)
	}

	// If no IP found, return empty result
	if ip == "" {
		return []*events.Event{}, nil
	}
	event.IP = ip

	// Extract URL using configured method
	var url string
	switch settings.URLMethod {
	case "url_body_wrapper":
		url = urlBodyWrapper(serializedEmail)
	case "url_parts_0_body_raw_http_nl":
		url = urlParts0BodyRawHTTPNL(serializedEmail)
	case "url_body_hxxp_nl":
		url = urlBodyHxxpNL(serializedEmail)
	case "url_parts_0_body_raw_hxxp_nl":
		url = urlParts0BodyRawHxxpNL(serializedEmail)
	}

	if url != "" {
		event.URL = strings.TrimSpace(url)
	}

	// Set event type to Phishing
	event.EventTypes = []events.EventType{events.NewPhishing()}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 15
}
