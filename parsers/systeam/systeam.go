package systeam

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
	// Get subject - throws error if not found (throws=True in Python)
	subject, err := common.GetSubject(serializedEmail, true)
	if err != nil {
		return nil, err
	}
	subjectLower := strings.ToLower(subject)

	// Create event
	event := events.NewEvent("systeam")

	// Set event date from email headers
	if dateHeader, ok := serializedEmail.Headers["date"]; ok && len(dateHeader) > 0 {
		parsedDate := email.ParseDate(dateHeader[0])
		event.EventDate = parsedDate
	}

	// Set IP from subject (Python: event.ip = subject_lower)
	event.IP = subjectLower

	// Get body and check for evidence
	body, _ := common.GetBody(serializedEmail, false)
	if strings.Contains(body, "as evidence") {
		evidenceURL := strings.TrimSpace(common.FindStringWithoutMarkers(body, "as evidence ---", "---"))
		if evidenceURL != "" {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{
				URL: evidenceURL,
			})
			event.AddEventDetail(evidence)
		}
	}

	// Extract type from subject between [ and ]
	typeCandidate := common.FindStringWithoutMarkers(subjectLower, "[", "]")
	typeCandidate = strings.ReplaceAll(typeCandidate, " ", "_")

	// If no type found in brackets, look for specific keywords
	if typeCandidate == "" {
		keywords := []string{"fraud"}
		for _, word := range keywords {
			if strings.Contains(subjectLower, word) {
				typeCandidate = word
				break
			}
		}
	}

	// Convert incident type to event type
	if typeCandidate != "" {
		converted := common.IncidentTypeToEventType(typeCandidate)
		if converted != "" {
			// Map the type string to actual EventType instances
			switch converted {
			case "spam":
				event.EventTypes = []events.EventType{events.NewSpam()}
			case "phishing":
				event.EventTypes = []events.EventType{events.NewPhishing()}
			case "bot":
				event.EventTypes = []events.EventType{events.NewBot("")}
			case "copyright":
				event.EventTypes = []events.EventType{events.NewCopyright("", "", "")}
			case "ddos":
				event.EventTypes = []events.EventType{events.NewDDoS()}
			case "fraud":
				event.EventTypes = []events.EventType{events.NewFraud()}
			case "login_attack":
				event.EventTypes = []events.EventType{events.NewLoginAttack("", "")}
			case "malware_hosting":
				event.EventTypes = []events.EventType{events.NewMalwareHosting()}
			case "malware":
				event.EventTypes = []events.EventType{events.NewMalware("")}
			case "web_hack":
				event.EventTypes = []events.EventType{events.NewWebHack()}
			case "blacklist":
				event.EventTypes = []events.EventType{events.NewBlacklist("")}
			case "compromised_microsoft_exchange":
				event.EventTypes = []events.EventType{events.NewCompromisedMicrosoftExchange()}
			case "compromised_website":
				event.EventTypes = []events.EventType{events.NewCompromisedWebsite("")}
			case "compromised_server":
				event.EventTypes = []events.EventType{events.NewCompromisedServer()}
			case "compromised_account":
				event.EventTypes = []events.EventType{events.NewCompromisedAccount("")}
			case "ddos_amplification":
				event.EventTypes = []events.EventType{events.NewDDosAmplification("", "")}
			case "outdated_dnssec":
				event.EventTypes = []events.EventType{events.NewOutdatedDNSSEC()}
			case "ssl_poodle":
				event.EventTypes = []events.EventType{events.NewSSLPoodle()}
			case "ssl_freak":
				event.EventTypes = []events.EventType{events.NewSSLFreak("")}
			case "cve":
				event.EventTypes = []events.EventType{events.NewCVE("", "", "")}
			case "ip_spoof":
				event.EventTypes = []events.EventType{events.NewIPSpoof("", "", false, "")}
			case "port_scan":
				event.EventTypes = []events.EventType{events.NewPortScan()}
			case "exploit":
				event.EventTypes = []events.EventType{events.NewExploit()}
			case "trademark":
				event.EventTypes = []events.EventType{events.NewTrademark("", nil, "", "")}
			case "illegal_advertisement":
				event.EventTypes = []events.EventType{events.NewIllegalAdvertisement()}
			case "malicious_activity":
				event.EventTypes = []events.EventType{events.NewMaliciousActivity()}
			case "spamvertised":
				event.EventTypes = []events.EventType{events.NewSpamvertised()}
			case "dns_blocklist":
				event.EventTypes = []events.EventType{events.NewDNSBlocklist()}
			case "child_abuse":
				event.EventTypes = []events.EventType{events.NewChildAbuse()}
			case "doxing":
				event.EventTypes = []events.EventType{events.NewDoxing()}
			case "web_crawler":
				event.EventTypes = []events.EventType{events.NewWebCrawler()}
			case "rogue_dns":
				event.EventTypes = []events.EventType{events.NewRogueDNS()}
			case "defacement":
				event.EventTypes = []events.EventType{events.NewDefacement()}
			case "unknown":
				event.EventTypes = []events.EventType{events.NewUnknown()}
			case "violence":
				event.EventTypes = []events.EventType{events.NewViolence()}
			case "propaganda":
				event.EventTypes = []events.EventType{events.NewPropaganda()}
			case "auth_failure":
				event.EventTypes = []events.EventType{events.NewAuthFailure()}
			case "backdoor":
				event.EventTypes = []events.EventType{events.NewBackdoor()}
			case "open":
				// For open types, extract service name if present
				service := ""
				if strings.HasPrefix(typeCandidate, "open_") {
					service = strings.TrimPrefix(typeCandidate, "open_")
				}
				event.EventTypes = []events.EventType{events.NewOpen(service)}
			default:
				// Unknown type - raise NewTypeError as in Python
				return nil, common.NewNewTypeError(subjectLower)
			}
		} else {
			// Conversion failed - raise NewTypeError as in Python
			return nil, common.NewNewTypeError(subjectLower)
		}
	} else {
		// No type candidate found - raise NewTypeError
		return nil, common.NewNewTypeError(subjectLower)
	}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
