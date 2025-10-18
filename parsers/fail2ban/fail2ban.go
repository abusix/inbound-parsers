// Package fail2ban implements the fail2ban parser
package fail2ban

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser implements the fail2ban parser
type Parser struct{}

var (
	// SIMPLE_TIME_FINDER = re.compile(r'\w+\s+\d\d?\s+\d?\d:\d\d:\d\d')
	simpleTimeFinder = regexp.MustCompile(`\w+\s+\d\d?\s+\d?\d:\d\d:\d\d`)
	// FULL_TIME_FINDER = re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(,\d{3})?)')
	fullTimeFinder = regexp.MustCompile(`(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(,\d{3})?)`)
	// BEST_DATE_FINDER = re.compile(r'(?P<date>\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})')
	bestDateFinder = regexp.MustCompile(`(?P<date>\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})`)
	// PORT_FINDER = re.compile(r'(?:\s|\W|^)port:?\s(\d+)')
	portFinder = regexp.MustCompile(`(?:\s|\W|^)port:?\s(\d+)`)
	// Intrusion pattern with optional type (ddos, etc.)
	intrusionFinder = regexp.MustCompile(`following intrusion (\w* ?)attempts were detected:`)
)

// extractTarget extracts target IP from the body
func extractTarget(body string, event *events.Event) {
	// octet = find_string_without_markers(body, 'of that octet is', '.').strip()
	octet := strings.TrimSpace(common.FindStringWithoutMarkers(body, "of that octet is", "."))
	if octet != "" {
		// target_ip = find_string_without_markers(body, 'our ip is ').replace('[', '').replace(']', '').replace('x', octet)
		targetIP := common.FindStringWithoutMarkers(body, "our ip is ", "")
		targetIP = strings.ReplaceAll(targetIP, "[", "")
		targetIP = strings.ReplaceAll(targetIP, "]", "")
		targetIP = strings.ReplaceAll(targetIP, "x", octet)

		if targetIP != "" && common.IsIP(targetIP) != "" {
			target := &events.Target{IP: targetIP}
			event.AddEventDetail(target)
		}
	}
}

// getBlockAfter retrieves all lines after a marker
func getBlockAfter(body, marker string) []string {
	var result []string
	lines := strings.Split(body, "\n")
	found := false
	for _, line := range lines {
		if found {
			result = append(result, line)
		} else if strings.Contains(line, marker) {
			found = true
		}
	}
	return result
}

// extractLog parses log information and extracts date, port, and target details
func extractLog(body, receivedDate string, event *events.Event) {
	var block []string
	tz := "+0000"

	if strings.Contains(body, "attempts were detected") {
		block = getBlockAfter(body, "following intrusion")
		if len(block) > 1 && strings.Contains(block[0], "srcip:srcport") {
			// This log is in a table style
			// date, src, dst, proto, flags, packets, bytes, reason.
			entries := strings.Fields(block[len(block)-1])
			if len(entries) >= 7 {
				event.EventDate = email.ParseDate(entries[0])
				// event.port = entries[1].split(':')[1]
				srcParts := strings.Split(entries[1], ":")
				if len(srcParts) == 2 {
					if port, err := strconv.Atoi(srcParts[1]); err == nil {
						event.Port = port
					}
				}
				// dst_ip, dst_port = entries[2].split(':')
				dstParts := strings.Split(entries[2], ":")
				if len(dstParts) == 2 {
					dstIP := dstParts[0]
					dstPort := dstParts[1]
					target := &events.Target{IP: dstIP, Port: dstPort}
					event.AddEventDetail(target)
				}
				// event.add_event_detail(TransportProtocol(protocol=entries[3]))
				if len(entries) > 3 {
					proto := &events.TransportProtocol{Protocol: entries[3]}
					event.AddEventDetail(proto)
				}
				// event.add_event_detail(TrafficStats(packet_count=int(entries[5]), byte_count=int(entries[6])))
				if len(entries) > 6 {
					packetCount, err1 := strconv.Atoi(entries[5])
					byteCount, err2 := strconv.Atoi(entries[6])
					if err1 == nil && err2 == nil {
						stats := &events.TrafficStats{
							PacketCount: packetCount,
							ByteCount:   byteCount,
						}
						event.AddEventDetail(stats)
					}
				}
			}
		}
	} else if strings.Contains(body, "excerpt from log") {
		block = getBlockAfter(body, "excerpt from log")
		if len(block) > 1 && strings.Contains(block[0], "local timezone is") {
			// tz = re.search(r'[+\-]\d+', block[0]).group(0)
			tzMatch := regexp.MustCompile(`[+\-]\d+`).FindString(block[0])
			if tzMatch != "" {
				tz = tzMatch
			}
			block = block[1:]
		}
	}

	// Find port if not already set
	if event.Port == 0 {
		for _, line := range block {
			if matches := portFinder.FindStringSubmatch(line); len(matches) > 1 {
				if port, err := strconv.Atoi(matches[1]); err == nil {
					event.Port = port
					break
				}
			}
		}
	}

	// Find date
	dateStr := ""
	for _, line := range block {
		if match := simpleTimeFinder.FindString(line); match != "" {
			// received_year = magic_datetime_parser(received_date).year
			var receivedYear string
			if parsedReceived := email.ParseDate(receivedDate); parsedReceived != nil {
				receivedYear = fmt.Sprintf("%d", parsedReceived.Year())
			}
			// info = time_match.group().strip()
			info := strings.TrimSpace(match)
			// year = str(received_year)
			// month, day, time = info.split()
			parts := strings.Fields(info)
			if len(parts) >= 3 {
				month := parts[0]
				day := parts[1]
				timeStr := parts[2]
				// date_str = ' '.join([day, month, year, time])
				dateStr = fmt.Sprintf("%s %s %s %s", day, month, receivedYear, timeStr)
			}
			break
		} else if match := fullTimeFinder.FindStringSubmatch(line); len(match) > 1 {
			dateStr = strings.TrimSpace(match[1])
			break
		} else if match := bestDateFinder.FindStringSubmatch(line); len(match) > 1 {
			dateStr = strings.TrimSpace(match[1])
			break
		}
	}

	if dateStr != "" {
		// event.event_date = ' '.join([date_str.split(',')[0], tz])
		dateParts := strings.Split(dateStr, ",")
		finalDateStr := fmt.Sprintf("%s %s", dateParts[0], tz)
		event.EventDate = email.ParseDate(finalDateStr)
	}
}

// Parse parses fail2ban abuse reports
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, err := common.GetBody(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	subject, err := common.GetSubject(serializedEmail, false)
	if err != nil {
		return nil, err
	}

	event := events.NewEvent("fail2ban")

	// Determine event type
	bodyLower := strings.ToLower(body)
	var eventType events.EventType = events.NewLoginAttack("", "")

	if strings.Contains(bodyLower, "postfix") || strings.Contains(bodyLower, "smtp") {
		eventType = events.NewSpam()
	}

	// Check for intrusion type
	hasLog := strings.Contains(bodyLower, "excerpt from log")
	if matches := intrusionFinder.FindStringSubmatch(bodyLower); len(matches) > 1 {
		hasLog = true
		if strings.TrimSpace(matches[1]) != "" {
			if strings.Contains(matches[1], "ddos") {
				eventType = events.NewDDoS()
			}
			// else: raise NewTypeError(result.group(1))
			// We'll just use the default login attack for unknown types
		}
	}

	event.EventTypes = []events.EventType{eventType}

	// Extract IP from subject or body
	subjectIP := common.ExtractOneIP(subject)
	if subjectIP != "" && common.IsIP(subjectIP) != "" {
		event.IP = common.IsIP(subjectIP)
	} else {
		// event.ip = find_string_without_markers(body, 'IP address', ',')
		ipStr := common.FindStringWithoutMarkers(body, "IP address", ",")
		if ipStr != "" {
			cleanIP := common.IsIP(ipStr)
			if cleanIP != "" {
				event.IP = cleanIP
			}
		}
	}

	// Get received date from headers
	var receivedDate string
	if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
		receivedDate = dateHeaders[0]
	}

	// Extract log information
	if hasLog {
		extractLog(bodyLower, receivedDate, event)
	}

	// Try to get event date from 'generated at' if not already set
	if event.EventDate == nil && strings.Contains(body, "generated at") {
		dateStr := strings.TrimSpace(common.FindStringWithoutMarkers(body, "generated at", ""))
		if dateStr != "" {
			event.EventDate = email.ParseDate(dateStr)
		}
	}

	// Fall back to received date if event date is still not set
	if event.EventDate == nil && receivedDate != "" {
		event.EventDate = email.ParseDate(receivedDate)
	}

	// Extract target IP
	extractTarget(bodyLower, event)

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
