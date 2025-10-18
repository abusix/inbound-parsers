package dmarc_xml

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser handles DMARC XML report parsing
type Parser struct{}

// NewParser creates a new DMARC XML parser
func NewParser() *Parser {
	return &Parser{}
}

var (
	// XML entity reference pattern to fix malformed XML
	xmlEntityRefPattern = regexp.MustCompile(`&(?!\w+;)`)

	// Valid sender addresses for DMARC reports
	validFroms = map[string]bool{
		"noreply-dmarc-support@google.com":        true,
		"noreply@dmarc.yahoo.com":                 true,
		"abuse@126.com":                           true,
		"abuse@163.com":                           true,
		"dmarc_support@corp.mail.ru":              true,
		"dmarc-support@alerts.comcast.net":        true,
		"dmarcrep@microsoft.com":                  true,
		"noreply@dmarc-reports.xs4all.net":        true,
		"postmaster@blackops.org":                 true,
		"dmarc-noreply@ivenue.com":                true,
		"postmaster@junc.org":                     true,
		"noreply-dmarc@numeezy.com":               true,
		"dmarc-noreply@linkedin.com":              true,
		"reporter@dmarc.andreasschulze.de":        true,
		"abuse@yeah.net":                          true,
		"postmaster@inteligis.ro":                 true,
		"sysops@g3nius.net":                       true,
		"postmaster@dmarc.org":                    true,
		"postmaster@laussat.info":                 true,
		"report@dmarc.laussat.info":               true,
		"postmaster@sentrion.eu":                  true,
		"postmaster@databus.com":                  true,
		"abuse_dmarc@abuse.aol.com":               true,
		"postmaster@miu08.de":                     true,
		"MAILER-DAEMON@mail1.veltins.de":          true,
		"postmaster+dmarcreports@ruhr-uni-bochum.de": true,
	}
)

// DMARC XML structures
type Feedback struct {
	XMLName        xml.Name       `xml:"feedback"`
	ReportMetadata ReportMetadata `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records        []Record       `xml:"record"`
}

type ReportMetadata struct {
	Email     string    `xml:"email"`
	DateRange DateRange `xml:"date_range"`
}

type DateRange struct {
	Begin string `xml:"begin"`
	End   string `xml:"end"`
}

type PolicyPublished struct {
	Domain string `xml:"domain"`
}

type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

type Row struct {
	SourceIP string `xml:"source_ip"`
}

type Identifiers struct {
	HeaderFrom string `xml:"header_from"`
}

type AuthResults struct {
	SPF  SPFResult  `xml:"spf"`
	DKIM DKIMResult `xml:"dkim"`
}

type SPFResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

type DKIMResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

// Parse implements the Parser interface
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var eventsList []*events.Event

	// Determine content type
	contentType := getContentType(serializedEmail)

	// Check if this is a DMARC report
	if !isDMARCReport(serializedEmail, contentType) {
		return nil, common.NewParserError("not a DMARC report")
	}

	switch contentType {
	case "multipart/mixed":
		events, err := parseMultipartMixed(serializedEmail)
		if err != nil {
			return nil, err
		}
		eventsList = append(eventsList, events...)

	case "application/gzip", "application/x-gzip":
		events, err := parseGzip(serializedEmail)
		if err != nil {
			return nil, err
		}
		eventsList = append(eventsList, events...)

	case "application/zip", "application/x-zip-compressed":
		events, err := parseZip(serializedEmail)
		if err != nil {
			return nil, err
		}
		eventsList = append(eventsList, events...)

	default:
		return nil, common.NewParserError("unsupported content type: " + contentType)
	}

	if len(eventsList) == 0 {
		return nil, common.NewParserError("no events generated from DMARC report")
	}

	return eventsList, nil
}

// getContentType extracts the content type from email headers
func getContentType(serializedEmail *email.SerializedEmail) string {
	if ct, ok := serializedEmail.Headers["content-type"]; ok && len(ct) > 0 {
		contentType := strings.ToLower(ct[0])
		// Extract just the main type
		if idx := strings.Index(contentType, ";"); idx > 0 {
			contentType = strings.TrimSpace(contentType[:idx])
		}
		return contentType
	}
	return ""
}

// isDMARCReport checks if this email is a DMARC report
func isDMARCReport(serializedEmail *email.SerializedEmail, contentType string) bool {
	// Check valid from address
	if from, ok := serializedEmail.Headers["from"]; ok && len(from) > 0 {
		fromAddr := strings.ToLower(from[0])
		// Extract email address from "Name <email>" format
		if idx := strings.LastIndex(fromAddr, "<"); idx >= 0 {
			fromAddr = fromAddr[idx+1:]
			fromAddr = strings.TrimSuffix(fromAddr, ">")
		}
		fromAddr = strings.TrimSpace(fromAddr)

		if validFroms[fromAddr] {
			if contentType == "application/zip" || contentType == "multipart/mixed" ||
			   contentType == "application/gzip" || contentType == "application/x-gzip" ||
			   contentType == "application/x-zip-compressed" {
				return true
			}
		}
	}

	// Check subject line
	if subject, ok := serializedEmail.Headers["subject"]; ok && len(subject) > 0 {
		if strings.HasPrefix(subject[0], "Report Domain:") {
			return true
		}
	}

	return false
}

// parseMultipartMixed handles multipart/mixed emails
func parseMultipartMixed(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	for _, part := range serializedEmail.Parts {
		contentType := getPartContentType(part)

		if strings.Contains(contentType, "gzip") || strings.Contains(contentType, "x-gzip") ||
		   strings.Contains(contentType, ".gz") {
			// Parse as gzip
			return parsePartGzip(part)
		} else if strings.Contains(contentType, "zip") || strings.Contains(contentType, "x-zip-compressed") ||
		          strings.Contains(contentType, ".zip") {
			// Parse as zip
			return parsePartZip(part)
		}
	}

	return nil, common.NewParserError("no gzip or zip attachment found in multipart email")
}

// getPartContentType extracts content type from an email part
func getPartContentType(part email.EmailPart) string {
	if part.Headers != nil {
		if ct, ok := part.Headers["content-type"]; ok && len(ct) > 0 {
			return strings.ToLower(ct[0])
		}
	}
	return strings.ToLower(part.ContentType)
}

// parseGzip handles application/gzip content type
func parseGzip(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var bodyData []byte
	var err error

	// Try to decode base64 first
	if bodyStr, ok := serializedEmail.Body.(string); ok {
		bodyData, err = base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			// If base64 decode fails, use raw body
			bodyData = []byte(bodyStr)
		}
	} else if bodyBytes, ok := serializedEmail.Body.([]byte); ok {
		bodyData = bodyBytes
	} else {
		return nil, common.NewParserError("invalid body type for gzip")
	}

	return extractFromGzip(bodyData)
}

// parseZip handles application/zip content type
func parseZip(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	var bodyData []byte
	var err error

	// Try to decode base64 first
	if bodyStr, ok := serializedEmail.Body.(string); ok {
		bodyData, err = base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			// If base64 decode fails, use raw body
			bodyData = []byte(bodyStr)
		}
	} else if bodyBytes, ok := serializedEmail.Body.([]byte); ok {
		bodyData = bodyBytes
	} else {
		return nil, common.NewParserError("invalid body type for zip")
	}

	return extractFromZip(bodyData)
}

// parsePartGzip handles gzip attachment from a part
func parsePartGzip(part email.EmailPart) ([]*events.Event, error) {
	var bodyData []byte
	var err error

	if bodyStr, ok := part.Body.(string); ok {
		bodyData, err = base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			bodyData = []byte(bodyStr)
		}
	} else if bodyBytes, ok := part.Body.([]byte); ok {
		bodyData = bodyBytes
	} else {
		return nil, common.NewParserError("invalid part body type for gzip")
	}

	return extractFromGzip(bodyData)
}

// parsePartZip handles zip attachment from a part
func parsePartZip(part email.EmailPart) ([]*events.Event, error) {
	var bodyData []byte
	var err error

	if bodyStr, ok := part.Body.(string); ok {
		bodyData, err = base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			bodyData = []byte(bodyStr)
		}
	} else if bodyBytes, ok := part.Body.([]byte); ok {
		bodyData = bodyBytes
	} else {
		return nil, common.NewParserError("invalid part body type for zip")
	}

	return extractFromZip(bodyData)
}

// extractFromGzip extracts and parses XML from gzip data
func extractFromGzip(gzipData []byte) ([]*events.Event, error) {
	reader, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip: %w", err)
	}
	defer reader.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip content: %w", err)
	}

	return parseXMLContent(buf.Bytes())
}

// extractFromZip extracts and parses XML from zip data
func extractFromZip(zipData []byte) ([]*events.Event, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	var allEvents []*events.Event

	// Process all files in the zip
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			continue // Skip files that can't be opened
		}

		var buf bytes.Buffer
		_, err = buf.ReadFrom(rc)
		rc.Close()

		if err != nil {
			continue // Skip files that can't be read
		}

		events, err := parseXMLContent(buf.Bytes())
		if err != nil {
			continue // Skip files that can't be parsed
		}

		allEvents = append(allEvents, events...)
	}

	if len(allEvents) == 0 {
		return nil, common.NewParserError("no valid DMARC XML found in zip")
	}

	return allEvents, nil
}

// parseXMLContent parses DMARC XML and creates events
func parseXMLContent(xmlData []byte) ([]*events.Event, error) {
	// Clean the XML content
	content := string(xmlData)

	// Fix common XML issues
	content = strings.ReplaceAll(content, "><><", ">&lt;&gt;<")
	content = xmlEntityRefPattern.ReplaceAllString(content, "&amp;")

	// Try to find <feedback> tag if full XML is not valid
	if !strings.Contains(content, "<?xml") {
		if idx := strings.Index(content, "<feedback>"); idx >= 0 {
			content = content[idx:]
		}
	}

	// Parse XML
	var feedback Feedback
	err := xml.Unmarshal([]byte(content), &feedback)
	if err != nil {
		// Try one more time, looking for feedback tag
		if idx := strings.Index(content, "<feedback>"); idx >= 0 {
			content = content[idx:]
			err = xml.Unmarshal([]byte(content), &feedback)
			if err != nil {
				return nil, fmt.Errorf("failed to parse DMARC XML: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse DMARC XML: %w", err)
		}
	}

	// Extract metadata
	reporterEmail := feedback.ReportMetadata.Email
	domain := feedback.PolicyPublished.Domain

	// Parse dates
	var dateBegin, dateEnd *time.Time
	if feedback.ReportMetadata.DateRange.Begin != "" {
		if ts, err := strconv.ParseInt(feedback.ReportMetadata.DateRange.Begin, 10, 64); err == nil {
			t := time.Unix(ts, 0)
			dateBegin = &t
		}
	}
	if feedback.ReportMetadata.DateRange.End != "" {
		if ts, err := strconv.ParseInt(feedback.ReportMetadata.DateRange.End, 10, 64); err == nil {
			t := time.Unix(ts, 0)
			dateEnd = &t
		}
	}

	// Create events for each record
	var eventsList []*events.Event
	for _, record := range feedback.Records {
		// Validate IP
		ip := common.IsIP(record.Row.SourceIP)
		if ip == "" {
			continue // Skip records without valid IP
		}

		// Create event
		event := events.NewEvent("dmarc_xml")
		event.IP = ip
		event.URL = domain
		event.EventDate = dateBegin
		event.EventTypes = []events.EventType{events.NewAuthFailure()}

		// Add date_end as evidence
		if dateEnd != nil {
			evidence := &events.Evidence{}
			evidence.AddEvidence(events.UrlStore{
				Description: "date_end",
				URL:         dateEnd.Format("2006-01-02 15:04:05"),
			})
			event.AddEventDetail(evidence)
		}

		// Add SPF detail
		spf := &events.SPF{
			Domain: record.AuthResults.SPF.Domain,
			Result: record.AuthResults.SPF.Result,
		}
		event.AddEventDetail(spf)

		// Add DKIM detail
		dkim := &events.DKIM{
			Domain: record.AuthResults.DKIM.Domain,
			Result: record.AuthResults.DKIM.Result,
		}
		event.AddEventDetail(dkim)

		// Add reporter organization
		reporter := &events.Organisation{
			Name:         "reporter",
			ContactEmail: reporterEmail,
			URLOrDomain:  record.Identifiers.HeaderFrom,
		}
		event.AddEventDetail(reporter)

		eventsList = append(eventsList, event)
	}

	return eventsList, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
