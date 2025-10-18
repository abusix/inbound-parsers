package cloudflare

import (
	"regexp"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Check if this is from notify.cloudflare.com
	fromAddr := ""
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr = from[0]
	}

	if strings.Contains(fromAddr, "notify.cloudflare.com") {
		return parseNotifyCloudflare(serializedEmail)
	}

	return parseRegularCloudflare(serializedEmail)
}

// parseNotifyCloudflare handles emails from notify.cloudflare.com
func parseNotifyCloudflare(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	body = common.RemoveCarriageReturn(body)

	subject, _ := common.GetSubject(serializedEmail, false)

	// Get date from email header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Parse reporter info
	reporterInfo := parseReporterInfo(body)

	// Parse event type
	eventType := parseSpecificEventType(body, subject)

	// Extract URLs
	urls := common.GetContinuousLinesUntilEmptyLine(body, "Reported URLs:")
	if len(urls) == 0 {
		urls = common.GetContinuousLinesUntilEmptyLine(body, "Accepted URL(s)")
	}

	// Extract IPs
	var ips []string
	if strings.Contains(body, "Associated IP Addresses:") {
		ipStr := common.FindStringWithoutMarkers(body, "Associated IP Addresses:", "")
		ipList := strings.Split(ipStr, ",")
		for _, ip := range ipList {
			ips = append(ips, strings.TrimSpace(ip))
		}
	} else if strings.Contains(body, "IP address: curl") {
		ip := common.ExtractOneIP(common.FindStringWithoutMarkers(body, "IP address: curl", ""))
		if ip != "" {
			ips = append(ips, ip)
		}
	} else {
		ipStr := common.FindStringWithoutMarkers(body, "following IP addresses.", ". ")
		ipList := strings.Split(ipStr, ",")
		for _, ip := range ipList {
			ips = append(ips, strings.TrimSpace(ip))
		}
	}

	// Handle URL/IP pairing
	var results []*events.Event

	// If we have fewer URLs than IPs, repeat the first URL
	// If we have more URLs than IPs (and only 1 IP), repeat the IP
	maxLen := len(urls)
	if len(ips) > maxLen {
		maxLen = len(ips)
	}

	for i := 0; i < maxLen; i++ {
		var url, ip string

		if len(urls) > 0 {
			if i < len(urls) {
				url = strings.TrimSpace(urls[i])
			} else {
				url = strings.TrimSpace(urls[0])
			}
		}

		if len(ips) > 0 {
			if i < len(ips) {
				ip = ips[i]
			} else if len(ips) == 1 {
				ip = ips[0]
			}
		}

		event := createOneEvent(eventDate, url, ip, reporterInfo, eventType)
		results = append(results, event)
	}

	return results, nil
}

// parseRegularCloudflare handles regular cloudflare.com emails
func parseRegularCloudflare(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	subject, _ := common.GetSubject(serializedEmail, false)

	ip := common.ExtractOneIP(body)
	ip = common.IsIP(ip)

	// Get date from email header
	var eventDate *time.Time
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		eventDate = email.ParseDate(dateHeader[0])
	}

	// Determine event type from subject
	var eventType events.EventType
	if strings.Contains(subject, "DMCA copyright") {
		eventType = events.NewCopyright("", "", "")
	} else if strings.Contains(subject, "phishing report") {
		eventType = events.NewPhishing()
	} else if strings.Contains(subject, "abuse report") {
		eventType = events.NewFraud()
	} else if strings.Contains(subject, "trademark infringement") {
		eventType = events.NewTrademark("", nil, "", "")
	} else if strings.Contains(subject, "Spamhaus SBL listing") {
		eventType = events.NewBlacklist("SBL")
	} else if strings.Contains(subject, "child pornography report") {
		eventType = events.NewChildAbuse()
	}

	// Extract URLs from body
	var results []*events.Event
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if line == "Reported URLs:" {
			// Collect URLs starting from 2 lines after
			for j := i + 2; j < len(lines); j++ {
				content := strings.TrimSpace(lines[j])
				if !strings.HasPrefix(content, "http") {
					break
				}
				event := events.NewEvent("cloudflare")
				event.IP = ip
				event.EventDate = eventDate
				event.URL = content
				event.EventTypes = []events.EventType{eventType}
				results = append(results, event)
			}
			break
		}
	}

	return results, nil
}

// parseReporterInfo extracts reporter information from body
func parseReporterInfo(body string) *events.Organisation {
	if strings.Contains(body, "Reporter: Anonymous") {
		return nil
	}

	reporterInfo := &events.Organisation{
		Name: "reporter",
	}

	for _, line := range common.GetBlockAround(body, "Reporter's") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		value := strings.TrimSpace(parts[1])

		if strings.Contains(line, "Email") {
			reporterInfo.ContactEmail = value
		} else if strings.Contains(line, "Company Name") {
			reporterInfo.Organisation = value
		} else if strings.Contains(line, "Telephone") {
			reporterInfo.ContactPhone = value
		} else if strings.Contains(line, "Address") {
			reporterInfo.Address = value
		} else if strings.Contains(line, "Reporter's Name") {
			reporterInfo.ContactName = value
		}
	}

	return reporterInfo
}

// parseSpecificEventType determines the specific event type from body and subject
func parseSpecificEventType(body, subject string) events.EventType {
	bodyLower := strings.ToLower(body)

	// DMCA Copyright
	if strings.Contains(subject, "DMCA") {
		url := common.GetNonEmptyLineAfter(body, "Original URL:")
		var work, copyrightOwner string

		if url == "" {
			originalWork := strings.TrimSpace(common.FindStringWithoutMarkers(body, "Original Work", "Please address"))
			if strings.Contains(originalWork, "http") {
				parts := strings.SplitN(originalWork, "http", 2)
				work = strings.TrimSpace(parts[0])
				if len(parts) > 1 {
					url = "http" + parts[1]
				}
			}
		}

		copyrightOwner = strings.TrimSpace(common.FindStringWithoutMarkers(body, "Copyright Holder's Name:", ""))
		copyright := events.NewCopyright(work, copyrightOwner, "")
		copyright.OfficialURL = url
		return copyright
	}

	// Child Abuse
	if strings.Contains(subject, "child pornography report") ||
		strings.Contains(bodyLower, "pedophile") ||
		strings.Contains(bodyLower, "minors") ||
		(strings.Contains(bodyLower, "sexual abuse") && strings.Contains(bodyLower, "child")) {
		return events.NewChildAbuse()
	}

	// Trademark
	if strings.Contains(subject, "trademark infringement") || strings.Contains(bodyLower, "trademark") {
		regNumber := strings.Trim(common.FindStringWithoutMarkers(bodyLower, "registration number", ""), ":- ")
		regOffice := strings.Trim(common.FindStringWithoutMarkers(bodyLower, "registration office", ""), ":- ")

		var regNumbers []string
		if regNumber != "" {
			regNumbers = append(regNumbers, regNumber)
		}

		trademark := events.NewTrademark("", regNumbers, "", "")
		trademark.RegistrationOffice = regOffice
		return trademark
	}

	if strings.Contains(bodyLower, "without the right to use it") || strings.Contains(bodyLower, "brand identity") {
		return events.NewTrademark("", nil, "", "")
	}

	// Copyright (various indicators)
	if containsAny(bodyLower, []string{
		"non consensual nudity",
		"nudity pictures",
		"copy of my site",
		"copyrighted content",
		"online sexual abuse victims",
		"stolen",
		"infringe",
		"infringing",
		"copyright",
	}) || (strings.Contains(subject, "non-consensual") && strings.Contains(subject, "imagery")) ||
		strings.Contains(body, "Women's Human Rights") ||
		matchesPattern(bodyLower, `victim.*sex`) ||
		matchesPattern(bodyLower, `without.*permission`) ||
		matchesPattern(bodyLower, `website upload.*content in their website`) {
		return events.NewCopyright("", "", "")
	}

	// Phishing
	if strings.Contains(subject, "phishing") ||
		strings.Contains(body, "phishing") ||
		strings.Contains(bodyLower, "leads to another site") ||
		strings.Contains(bodyLower, "clone") {
		return events.NewPhishing()
	}

	// Malware
	if strings.Contains(bodyLower, "malware") ||
		strings.Contains(common.FindStringWithoutMarkers(body, "Logs or Evidence of Abuse:", ""), "virustotal.com") {
		return events.NewMalware("")
	}

	// Fraud (various patterns)
	if (strings.Contains(subject, "abuse report") && strings.Contains(bodyLower, "fraud")) ||
		strings.Contains(bodyLower, "voice over") ||
		containsAny(bodyLower, []string{
			"scam",
			"fake claims",
			"useless product",
			"pretended",
			"misleading information",
			"fake shop",
			"unsolicited text",
			"fake information",
			"malicious shortener",
		}) || matchesPattern(body, `money.*stolen`) ||
		matchesPattern(body, `email.*does not work`) {
		return events.NewFraud()
	}

	// Spam
	if strings.Contains(bodyLower, "spam") || strings.Contains(bodyLower, "stop sending") {
		return events.NewSpam()
	}

	// Doxing/Harassment
	if containsAny(bodyLower, []string{
		"harassment",
		"harassing",
		"taunt",
		"harassed",
		"defamation",
		"doxing",
		"doxxing",
		"pii sensitive data",
		"personal data",
		"reputation",
		"personal info",
		"my information",
		"verwijder mijn gegevens",
		"unproven incident",
		"blackmail",
		"page contains information",
		"my name",
		"personal and company-internal data",
	}) || matchesPattern(body, `information.*full name`) ||
		matchesPattern(body, `picture.*about me`) {
		return events.NewDoxing()
	}

	// Violence
	if strings.Contains(bodyLower, "violent behaviour") {
		return events.NewViolence()
	}

	// Propaganda
	if containsAny(bodyLower, []string{"propaganda", "terrorism", "terrorist"}) {
		return events.NewPropaganda()
	}

	// WebHack
	if strings.Contains(bodyLower, "cyber attack") || matchesPattern(body, `site.* hacked`) {
		return events.NewWebHack()
	}

	// Illegal Advertisement
	if containsAny(bodyLower, []string{
		"selling personal data",
		"sex trafficking",
		"illegal distribution",
	}) || (strings.Contains(bodyLower, "unlawful") && strings.Contains(bodyLower, "cannabis act of canada")) ||
		(strings.Contains(bodyLower, "dark web") && strings.Contains(body, "police investigation")) {
		return events.NewIllegalAdvertisement()
	}

	// Exploit
	if strings.Contains(bodyLower, "exploit content") {
		return events.NewExploit()
	}

	// IP Spoof
	if strings.Contains(bodyLower, "spoofing") {
		return events.NewIPSpoof("", "", false, "")
	}

	// Default to Unknown
	return events.NewUnknown()
}

// createOneEvent creates a single event with all the parsed information
func createOneEvent(date *time.Time, url, ip string, reporterInfo *events.Organisation, eventType events.EventType) *events.Event {
	event := events.NewEvent("cloudflare")
	event.URL = strings.TrimSpace(url)
	event.IP = ip
	event.EventDate = date
	if reporterInfo != nil {
		event.AddEventDetail(reporterInfo)
	}
	event.EventTypes = []events.EventType{eventType}
	return event
}

// Helper functions

func containsAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func matchesPattern(text, pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(text)
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
