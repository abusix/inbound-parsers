package feedback_loop

import (
	"encoding/base64"
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

// findValidDKIMSigForDomain finds a valid DKIM signature for the given domain
func findValidDKIMSigForDomain(domain string, authResults []string, dkimSignatures []string, cfblAddress string) string {
	found := false
	validDKIM := ""

	// Extract registered domain from input domain
	domainComparison := extractRegisteredDomain(domain)

	for _, authResult := range authResults {
		dkimDomain := common.FindStringWithoutMarkers(authResult, "header.d=", " ")

		// RFC requires exact match for strict, or the dkim_domain to be a parent of domain for relaxed
		dkimComparison := extractRegisteredDomain(dkimDomain)

		if domainComparison == dkimComparison {
			found = true
			if !strings.Contains(authResult, "dkim=pass") {
				// DKIM validation failed
				return ""
			}
			validDKIM = dkimDomain
		}
	}

	if !found {
		return ""
	}

	// Get the correct dkim signature for the domain
	for _, dkimSig := range dkimSignatures {
		if strings.Contains(dkimSig, "d="+validDKIM+";") {
			return dkimSig
		}
	}

	return ""
}

// verifyDKIMSignsCFBL checks if DKIM signature signs the CFBL-Address header
func verifyDKIMSignsCFBL(dkimSignature string) bool {
	if dkimSignature == "" {
		return false
	}

	dkimSignature = strings.ReplaceAll(dkimSignature, "\r\n\t", " ")
	dkimSignature = strings.ReplaceAll(dkimSignature, "\n\t", " ")

	signedHeaders := common.FindStringWithoutMarkers(dkimSignature, " h=", ";")
	headersList := strings.Split(signedHeaders, ":")

	for _, header := range headersList {
		if strings.TrimSpace(header) == "CFBL-Address" {
			return true
		}
	}

	return false
}

// verify performs DKIM verification according to RFC9477
func verify(cfblDomain, fromDomain string, authResults []string, headers map[string][]string, cfblAddress string) error {
	baseDomain := extractRegisteredDomain(fromDomain)
	dkimSignatures := headers["dkim-signature"]

	if cfblDomain == fromDomain {
		// strict check per sec. 3.1.2 of RFC9477
		dkimSig := findValidDKIMSigForDomain(cfblDomain, authResults, dkimSignatures, cfblAddress)
		if dkimSig == "" || !verifyDKIMSignsCFBL(dkimSig) {
			return common.NewParserError("CFBL DKIM check (strict) failed for CFBL address domain " + cfblDomain)
		}
	} else if strings.HasSuffix(cfblDomain, "."+baseDomain) {
		// relaxed check per sec. 3.1.3 of RFC9477
		dkimSig := findValidDKIMSigForDomain(fromDomain, authResults, dkimSignatures, cfblAddress)
		if dkimSig != "" && verifyDKIMSignsCFBL(dkimSig) {
			return nil
		}

		// Try the child domain
		dkimSig = findValidDKIMSigForDomain(cfblDomain, authResults, dkimSignatures, cfblAddress)
		if dkimSig != "" && verifyDKIMSignsCFBL(dkimSig) {
			return nil
		}

		return common.NewParserError("CFBL DKIM check (relaxed) failed for CFBL address domain " + cfblDomain)
	} else {
		// third-party check per sec. 3.1.3 of RFC9477
		dkimSig := findValidDKIMSigForDomain(fromDomain, authResults, dkimSignatures, cfblAddress)
		dkimSigCFBL := findValidDKIMSigForDomain(cfblDomain, authResults, dkimSignatures, cfblAddress)

		// Check for alignment
		if dkimSig != "" && verifyDKIMSignsCFBL(dkimSig) && dkimSigCFBL != "" && verifyDKIMSignsCFBL(dkimSigCFBL) {
			return nil
		}

		// Providers may accept presigned messages, these messages MUST NOT sign the CFBL headers
		if dkimSigCFBL != "" && verifyDKIMSignsCFBL(dkimSigCFBL) && (dkimSig == "" || !verifyDKIMSignsCFBL(dkimSig)) {
			return nil
		}

		return common.NewParserError("CFBL DKIM check (third-party) failed for CFBL address domain " + cfblDomain)
	}

	return nil
}

// extractRegisteredDomain extracts the registered domain (like tldextract in Python)
// Simplified version - extracts domain.tld from subdomain.domain.tld
func extractRegisteredDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// Parse parses a feedback loop email according to RFC9477
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get auth results - first part is hostname, rest are DKIM results
	authHeader := serializedEmail.Metadata.AuthHeader
	if authHeader == "" {
		return nil, common.NewParserError("NO_AUTH_HEADER")
	}

	authResults := strings.Split(authHeader, ";")[1:]

	// Check for CFBL-Address header
	hasCFBLAddress := false
	if _, exists := serializedEmail.Headers["cfbl-address"]; exists {
		hasCFBLAddress = true
	}

	// If not found, check MIME parts for embedded message/rfc822
	if !hasCFBLAddress {
		for _, part := range serializedEmail.Parts {
			if part.Headers != nil {
				if cfblAddr, exists := part.Headers["cfbl-address"]; exists && len(cfblAddr) > 0 {
					hasCFBLAddress = true
					serializedEmail.Headers = part.Headers
					// Update auth results if available in the embedded message
					if authResultHeaders, exists := part.Headers["authentication-results"]; exists && len(authResultHeaders) > 0 {
						authResults = strings.Split(authResultHeaders[0], ";")[1:]
					}
					break
				}
			}
		}
	}

	if !hasCFBLAddress {
		return nil, common.NewParserError("NO_CFBL_ADDRESS")
	}

	// Parse CFBL addresses
	cfblAddrs, exists := serializedEmail.Headers["cfbl-address"]
	if !exists || len(cfblAddrs) == 0 {
		return nil, common.NewParserError("NO_CFBL_ADDRESS")
	}

	cfblAddresses := strings.Split(cfblAddrs[0], ";")
	reportType := "arf" // default

	// Check for report type
	if rt := common.FindStringWithoutMarkers(cfblAddrs[0]+";", "report=", ";"); rt != "" {
		reportType = rt
		// Remove report type from addresses
		if len(cfblAddresses) > 0 {
			cfblAddresses = cfblAddresses[:len(cfblAddresses)-1]
		}
	}

	// Extract valid email addresses and domains
	cfblDomains := make(map[string]bool)
	emailRegex := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

	for i, addr := range cfblAddrs {
		if match := emailRegex.FindString(addr); match != "" {
			cfblAddrs[i] = match
			parts := strings.SplitN(match, "@", 2)
			if len(parts) == 2 {
				cfblDomains[parts[1]] = true
			}
		} else {
			return nil, common.NewParserError("CFBL_ADDRESS_INVALID")
		}
	}

	// Get From address domain
	fromAddr := serializedEmail.Metadata.EnvelopeFrom
	if fromAddr == "" {
		return nil, common.NewParserError("NO_FROM_ADDRESS")
	}

	fromParts := strings.SplitN(fromAddr, "@", 2)
	if len(fromParts) != 2 {
		return nil, common.NewParserError("INVALID_FROM_ADDRESS")
	}
	fromDomain := fromParts[1]

	// Verify DKIM for each CFBL domain
	for cfblDomain := range cfblDomains {
		if err := verify(cfblDomain, fromDomain, authResults, serializedEmail.Headers, cfblAddrs[0]); err != nil {
			return nil, err
		}
	}

	// Create event
	event := events.NewEvent("feedback_loop")
	event.EventTypes = []events.EventType{events.NewSpam()}

	// Extract event date from Received headers
	if receivedHeaders, exists := serializedEmail.Headers["received"]; exists && len(receivedHeaders) > 0 {
		received := email.NewReceivedHeader(receivedHeaders)
		eventDate := received.ReceivedDate(1)
		if eventDate == nil {
			eventDate = received.ReceivedDate(0)
		}
		event.EventDate = eventDate
	}

	// Extract IP from various headers
	for _, header := range []string{"x-abusix-originating-ip", "x-client-src", "x-originating-ip"} {
		if values, exists := serializedEmail.Headers[header]; exists && len(values) > 0 {
			if ip := common.IsIP(values[0]); ip != "" {
				event.IP = ip
				break
			}
		}
	}

	// If no IP found, try to extract from Received header
	if event.IP == "" {
		if receivedHeaders, exists := serializedEmail.Headers["received"]; exists && len(receivedHeaders) > 0 {
			guessedHeader := receivedHeaders[0]
			if len(receivedHeaders) > 1 {
				guessedHeader = receivedHeaders[1]
			}

			// Extract IP from the "from" part of the Received header
			parts := strings.Split(guessedHeader, "by")
			if len(parts) > 0 {
				allIPv4s := common.ExtractAllIPv4(parts[0])
				if len(allIPv4s) > 0 {
					event.IP = allIPv4s[len(allIPv4s)-1]
				} else {
					// Try IPv6
					if ip := common.ExtractOneIP(guessedHeader); ip != "" {
						event.IP = ip
					}
				}
			}
		}

		// If still no IP, return nil (don't log errors for this)
		if event.IP == "" {
			return nil, nil
		}
	}

	event.URL = fromDomain

	// Set headers
	event.Headers = make(map[string]interface{})
	event.Headers["cfbl-address"] = serializedEmail.Headers["cfbl-address"]
	event.Headers["cfbl-report-type"] = []string{reportType}

	if msgID, exists := serializedEmail.Headers["message-id"]; exists {
		event.Headers["message-id"] = msgID
	}

	// Set return-path
	if returnPath, exists := serializedEmail.Headers["return-path"]; exists {
		event.Headers["return-path"] = returnPath
	} else {
		event.Headers["return-path"] = []string{serializedEmail.Metadata.EnvelopeFrom}
	}

	if cfblFeedbackID, exists := serializedEmail.Headers["cfbl-feedback-id"]; exists {
		event.Headers["cfbl-feedback-id"] = cfblFeedbackID
	}

	// Add sample of complete original email
	if serializedEmail.ParsedMessage != nil {
		if msgBytes, ok := serializedEmail.ParsedMessage.([]byte); ok {
			sample := &events.Sample{
				ContentType: "message/rfc822",
				Encoding:    "base64",
				Description: "Complete original email",
				Payload:     base64.StdEncoding.EncodeToString(msgBytes),
			}
			event.AddEventDetail(sample)
		}
	}

	// Add requirement for IP and URL
	event.AddRequirement("fbl_ip_and_url", events.NewAndRequirement([]interface{}{"ip", "url"}))

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 11
}
