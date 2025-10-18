package netbuild

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Match returns true if the email is from netbuild
func Match(serializedEmail *email.SerializedEmail, fromAddr string) bool {
	return fromAddr == "abuse@netbuild.net"
}

// Parse processes the netbuild abuse email
func Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(body)

	// Get time and timezone
	timeStr := getValue(bodyLower, "time of abuse")
	tz := getValue(body, "Timezone")

	// Create event template
	eventTemplate := events.NewEvent("netbuild")
	if timeStr != "" && tz != "" {
		dateStr := timeStr + " " + tz
		if parsedDate := email.ParseDate(dateStr); parsedDate != nil {
			eventTemplate.EventDate = parsedDate
		}
	}

	// Get abuse type
	abuseType := getValue(bodyLower, "type of abuse")
	switch abuseType {
	case "brute-force":
		eventTemplate.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
	default:
		return nil, nil
	}

	// Get target information
	targets := common.GetBlockAfterWithStop(bodyLower, "attacked from your network", "")
	targetIP := ""
	for _, line := range targets {
		if extracted := common.ExtractOneIP(line); extracted != "" {
			targetIP = extracted
			break
		}
	}

	if port := getValue(bodyLower, "target port"); port != "" {
		target := &events.Target{
			IP:   targetIP,
			Port: port,
		}
		eventTemplate.AddEventDetail(target)
	}

	// Get source ASN
	if srcAS := getValue(bodyLower, "source asn"); srcAS != "" {
		asn := strings.TrimPrefix(strings.ToLower(srcAS), "as")
		eventTemplate.AddEventDetail(&events.ASN{ASN: asn})
	}

	// Get source IPs
	source := common.GetBlockAfterWithStop(bodyLower, "addresses have attacked", "")
	var result []*events.Event
	for _, line := range source {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eventCopy := *eventTemplate
		eventCopy.IP = line
		result = append(result, &eventCopy)
	}

	return result, nil
}

// getValue extracts value after key in format "key: value"
func getValue(body, key string) string {
	tmp := common.FindStringWithoutMarkers(body, key, "")
	if strings.Contains(tmp, ":") {
		parts := strings.SplitN(tmp, ":", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
