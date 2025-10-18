package tntelecom

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

// parseDate converts tntelecom's custom date format to ISO 8601
// Input format: "Fri Aug 3 9:37PM EST 2025" (or similar AM/PM formats)
// Output format: "Fri Aug 3 21:37:00 +05:00 2025"
func parseDate(attackDateStr string) string {
	// Extract the hour from the time portion
	parts := strings.Split(attackDateStr, ":")
	if len(parts) < 2 {
		return attackDateStr
	}

	hourPart := parts[0]
	spaceSplit := strings.Split(hourPart, " ")
	hourStr := spaceSplit[len(spaceSplit)-1]

	hour, err := strconv.Atoi(hourStr)
	if err != nil {
		return attackDateStr
	}

	// Handle PM time conversion
	if strings.Contains(attackDateStr, "PM") {
		hour = hour + 12
	}

	// Format hour with leading zero if needed
	var formattedHour string
	if hour <= 9 {
		formattedHour = "0" + strconv.Itoa(hour)
	} else {
		formattedHour = strconv.Itoa(hour)
	}

	// Extract minutes from the time portion
	var time string
	if strings.Contains(attackDateStr, "PM") {
		minutePart := strings.Split(parts[1], "PM")[0]
		time = formattedHour + ":" + minutePart + ":00"
	} else if strings.Contains(attackDateStr, "AM") {
		minutePart := strings.Split(parts[1], "AM")[0]
		time = formattedHour + ":" + minutePart + ":00"
	} else {
		time = formattedHour + ":" + parts[1] + ":00"
	}

	// Normalize whitespace and rebuild date string
	normalizedStr := regexp.MustCompile(` +`).ReplaceAllString(attackDateStr, " ")
	fields := strings.Split(normalizedStr, " ")

	// Reconstruct: "DayOfWeek Month Day Time Timezone Year"
	if len(fields) < 3 {
		return attackDateStr
	}

	attackDateStr = fmt.Sprintf("%s %s %s %s %s", fields[0], fields[1], fields[2], time, fields[len(fields)-1])

	// Replace EST with +05:00
	if strings.Contains(attackDateStr, "EST") {
		attackDateStr = strings.Replace(attackDateStr, "EST", "+05:00", 1)
	}

	return attackDateStr
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	fromAddr, _ := common.GetFrom(serializedEmail, false)

	event := events.NewEvent("tntelecom")
	event.SenderEmail = fromAddr

	// IP is in the subject line
	event.IP = subject

	// Extract information from body
	asn := strings.TrimSpace(common.FindStringWithoutMarkers(body, "intended for ", " "))
	server := strings.TrimSpace(common.FindStringWithoutMarkers(body, "our server", ","))
	attackDateStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "recently at", "with"))
	badUsername := strings.TrimSpace(common.FindStringWithoutMarkers(body, "username", "."))

	// Parse and set event date
	parsedDate := parseDate(attackDateStr)
	eventDate := email.ParseDate(parsedDate)
	event.EventDate = eventDate

	// Add event details
	event.AddEventDetail(&events.ASN{ASN: asn})
	event.AddEventDetail(&events.Target{URL: server})

	// Set event type
	event.EventTypes = []events.EventType{events.NewLoginAttack(badUsername, "")}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
