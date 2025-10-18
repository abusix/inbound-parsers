// Package enfappdetex implements the enfappdetex parser
// This is a multi-client trademark parser handling Microsoft, Meta, Apple, WhatsApp, and others
package enfappdetex

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the enfappdetex parser
type Parser struct{}

var (
	// Pre-compile all regex patterns
	microsoftPattern    = regexp.MustCompile(`(?i)enf\.microsoft\.\d+@enfappdetex\.com`)
	metaPattern         = regexp.MustCompile(`(?i)enf\.meta\.\d+@enfappdetex\.com`)
	trowepricePattern   = regexp.MustCompile(`(?i)enf\.troweprice\.\d+@enfappdetex\.com`)
	whatsappPattern     = regexp.MustCompile(`(?i)enf\.whatsapp\.\d+@enfappdetex\.com`)
	applePattern        = regexp.MustCompile(`(?i)enf\.apple\.\d+@enfappdetex\.com`)
	mojangPattern       = regexp.MustCompile(`(?i)enf\.mojang\.\d+@enfappdetex\.com`)
	cuehealthPattern    = regexp.MustCompile(`(?i)enf\.cuehealth\.\d+@enfappdetex\.com`)
	cvsAetnaPattern     = regexp.MustCompile(`(?i)enf\.cvs-aetna\.\d+@enfappdetex\.com`)
	spotifyPattern      = regexp.MustCompile(`(?i)enf\.spotify\.\d+@enfappdetex\.com`)
	aristocratllPattern = regexp.MustCompile(`(?i)enf\.aristocratll\.\d+@enfappdetex\.com`)
	facebookrlPattern   = regexp.MustCompile(`(?i)enf\.facebookrl\.\d+@enfappdetex\.com`)
)

// NewParser creates a new enfappdetex parser
func NewParser() *Parser {
	return &Parser{}
}

// getTrademarkType extracts trademark information from body
func getTrademarkType(body, trademarkOwner string) *events.Trademark {
	trademarkedMaterial := ""
	country := ""
	var registrationNumbers []string

	// Extract trademark
	if match := regexp.MustCompile(`(?i)trademark:\s*(.+)`).FindStringSubmatch(body); len(match) > 1 {
		trademarkedMaterial = strings.TrimSpace(match[1])
	}

	// Extract country
	if match := regexp.MustCompile(`(?i)country:\s*(.+)`).FindStringSubmatch(body); len(match) > 1 {
		country = strings.TrimSpace(match[1])
	}

	// Extract registration number
	if match := regexp.MustCompile(`(?i)registration no\.:\s*(.+)`).FindStringSubmatch(body); len(match) > 1 {
		registrationNumbers = []string{strings.TrimSpace(match[1])}
	}

	return events.NewTrademark(country, registrationNumbers, trademarkOwner, trademarkedMaterial)
}

// parseMicrosoft handles Microsoft trademark complaints
func parseMicrosoft(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract trademarked material
	trademarkedMaterial := strings.TrimSpace(
		common.FindStringWithoutMarkers(
			strings.ToLower(body),
			"but not limited to those trademarks listed below:",
			"such unauthorized use",
		),
	)

	event.EventTypes = []events.EventType{
		events.NewTrademark("", nil, "microsoft corporation", trademarkedMaterial),
	}

	// Extract URL
	url := strings.TrimSpace(
		common.FindStringWithoutMarkers(
			body,
			"As the ISP of the aforementioned",
			"URL,",
		),
	)
	event.URL = url

	return []*events.Event{event}, nil
}

// parseMeta handles Meta (Facebook) trademark complaints
func parseMeta(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{getTrademarkType(body, "meta platforms, inc.")}

	// Extract URL and IP
	if match := regexp.MustCompile(`(?i)your services to host (\S+) at (\S+)`).FindStringSubmatch(body); len(match) > 2 {
		event.URL = match[1]
		event.IP = match[2]
	}

	return []*events.Event{event}, nil
}

// parseTroweprice handles T. Rowe Price trademark complaints
func parseTroweprice(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{getTrademarkType(body, "t.rowe price group, inc.")}

	// Extract URL from subject
	if match := regexp.MustCompile(`(?i)notice of trademark abuse – (.+)`).FindStringSubmatch(subject); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

// parseWhatsapp handles WhatsApp trademark complaints
func parseWhatsapp(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{
		getTrademarkType(body, "whatsapp llc (delaware corporation)"),
	}

	// Extract URL and IP
	if match := regexp.MustCompile(`(?i)use of the domain name (\S+), at ip address (\S+)`).FindStringSubmatch(body); len(match) > 2 {
		event.URL = match[1]
		event.IP = match[2]
	}

	return []*events.Event{event}, nil
}

// parseApple handles Apple trademark complaints
func parseApple(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{
		events.NewTrademark("", nil, "apple inc.", ""),
	}

	// Extract URL from subject
	if match := regexp.MustCompile(`(?i)(\S+) intellectual property infringement`).FindStringSubmatch(subject); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

// parseMojang handles Mojang trademark complaints
func parseMojang(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	var registrationNumbers []string
	officialURL := ""

	// Extract registration number and official URL
	if match := regexp.MustCompile(`(?i)reg number:\s*(.+?)\s*-\s*(\S+)`).FindStringSubmatch(body); len(match) > 2 {
		registrationNumbers = []string{match[1]}
		officialURL = match[2]
	}

	trademark := events.NewTrademark("", registrationNumbers, "mojang ab", "")
	trademark.OfficialURL = officialURL
	event.EventTypes = []events.EventType{trademark}

	// Extract infringing URL
	if match := regexp.MustCompile(`(?i)infringing materials:\s*(\S+)`).FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

// parseCuehealth handles Cue Health trademark complaints
func parseCuehealth(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{getTrademarkType(body, "cue health, inc.")}

	// Extract URL
	if match := regexp.MustCompile(`(?i)the host of the domain name (\S+),`).FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

// parseCvsAetna handles CVS/Aetna trademark complaints
func parseCvsAetna(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Extract trademark
	trademark := common.FindStringWithoutMarkers(
		body,
		"the following trademark assets for its",
		"trademark",
	)
	trademark = strings.ReplaceAll(trademark, "\u201c", "")
	trademark = strings.ReplaceAll(trademark, "\u201d", "")
	trademark = strings.TrimSpace(trademark)

	// Extract registration numbers
	registrationNumbers := common.GetContinuousLinesUntilEmptyLine(body, "Registrations:")

	event.EventTypes = []events.EventType{
		events.NewTrademark("", registrationNumbers, "cvs pharmacy, inc.", trademark),
	}

	// Extract URL and IP
	if match := regexp.MustCompile(`(?i)has used your services to host (http\S+) at ([\d.]+)`).FindStringSubmatch(body); len(match) > 2 {
		event.URL = match[1]
		event.IP = match[2]
	}

	return []*events.Event{event}, nil
}

// parseSpotify handles Spotify trademark complaints
func parseSpotify(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{getTrademarkType(body, "spotify")}

	// Extract URL
	url := strings.TrimSpace(
		common.FindStringWithoutMarkers(
			body,
			"concerning the hosting and use of the domain name",
			",",
		),
	)
	event.URL = url

	return []*events.Event{event}, nil
}

// parseAristocratll handles Aristocrat trademark complaints
func parseAristocratll(serializedEmail *email.SerializedEmail, eventTemplate *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	eventTemplate.EventTypes = []events.EventType{
		getTrademarkType(body, "aristocrat technologies australia pty ltd"),
	}

	// Extract URL
	url := strings.TrimSpace(
		common.FindStringWithoutMarkers(body, "currently located at", "and the"),
	)
	eventTemplate.URL = url

	// Extract IPs (comma-separated list)
	ipListStr := strings.TrimSpace(
		common.FindStringWithoutMarkers(body, url+" at", "Trademark:"),
	)
	ipList := strings.Split(ipListStr, ",")

	// Create one event per IP
	var events []*events.Event
	for _, ip := range ipList {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			// Create a copy of the template event
			event := *eventTemplate
			event.IP = ip
			events = append(events, &event)
		}
	}

	return events, nil
}

// parseFacebookrl handles Facebook Reality Labs trademark complaints
func parseFacebookrl(serializedEmail *email.SerializedEmail, event *events.Event) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	event.EventTypes = []events.EventType{
		getTrademarkType(body, "facebook technologies, llc"),
	}

	// Extract URL
	if match := regexp.MustCompile(`(?i)use of the domain name (\S+)`).FindStringSubmatch(body); len(match) > 1 {
		event.URL = match[1]
	}

	return []*events.Event{event}, nil
}

// Parse parses emails for enfappdetex
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get From address
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = strings.ToLower(from[0])
	}

	// Create base event
	event := events.NewEvent("enfappdetex")

	// Set event date from headers
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		event.EventDate = email.ParseDate(dateHeaders[0])
	}

	// Route to appropriate sub-parser based on from address
	if microsoftPattern.MatchString(fromAddr) {
		return parseMicrosoft(serializedEmail, event)
	} else if metaPattern.MatchString(fromAddr) {
		return parseMeta(serializedEmail, event)
	} else if trowepricePattern.MatchString(fromAddr) {
		return parseTroweprice(serializedEmail, event)
	} else if whatsappPattern.MatchString(fromAddr) {
		return parseWhatsapp(serializedEmail, event)
	} else if applePattern.MatchString(fromAddr) {
		return parseApple(serializedEmail, event)
	} else if mojangPattern.MatchString(fromAddr) {
		return parseMojang(serializedEmail, event)
	} else if cuehealthPattern.MatchString(fromAddr) {
		return parseCuehealth(serializedEmail, event)
	} else if cvsAetnaPattern.MatchString(fromAddr) {
		return parseCvsAetna(serializedEmail, event)
	} else if spotifyPattern.MatchString(fromAddr) {
		return parseSpotify(serializedEmail, event)
	} else if aristocratllPattern.MatchString(fromAddr) {
		return parseAristocratll(serializedEmail, event)
	} else if facebookrlPattern.MatchString(fromAddr) {
		return parseFacebookrl(serializedEmail, event)
	}

	// Unknown sender - return NewTypeError
	return nil, common.NewNewTypeError(fromAddr)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
