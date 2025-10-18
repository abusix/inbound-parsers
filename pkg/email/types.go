// Package email provides email parsing and serialization types
package email

import (
	"strings"
	"time"
)

// SerializedEmail represents a fully parsed email message
// This matches the Python serialized_email structure
type SerializedEmail struct {
	Identifier      string                 `json:"identifier"`
	Headers         map[string][]string    `json:"headers"`
	Body            interface{}            `json:"body"`
	Parts           []EmailPart            `json:"parts"`
	Metadata        EmailMetadata          `json:"metadata"`
	Signature       map[string]interface{} `json:"signature,omitempty"`
	EnvelopeTo      []string               `json:"envelope_to,omitempty"`
	ParsedMessage   interface{}            `json:"parsed_message,omitempty"` // Original email.Message object
}

// EmailPart represents a MIME part of an email
type EmailPart struct {
	Body        interface{}         `json:"body"`
	Headers     map[string][]string `json:"headers,omitempty"`
	ContentType string              `json:"content_type,omitempty"`
	Parts       []EmailPart         `json:"parts,omitempty"` // Nested parts for multipart messages
}

// EmailMetadata contains email metadata
type EmailMetadata struct {
	EnvelopeFrom string `json:"envelope_from"`
	AuthHeader   string `json:"auth_header,omitempty"`
}

// ReceivedHeader represents a parsed Received header
type ReceivedHeader struct {
	Headers []string
}

// NewReceivedHeader creates a ReceivedHeader from the headers
func NewReceivedHeader(receivedHeaders []string) *ReceivedHeader {
	return &ReceivedHeader{
		Headers: receivedHeaders,
	}
}

// ReceivedDate extracts the received date from the specified header index
func (r *ReceivedHeader) ReceivedDate(index int) *time.Time {
	if index < 0 || index >= len(r.Headers) {
		return nil
	}

	header := r.Headers[index]

	// Extract date from "Received" header (typically after semicolon)
	// Format: "from ... by ... ; Thu, 18 Oct 2025 01:00:00 +0000"
	parts := strings.Split(header, ";")
	if len(parts) < 2 {
		return nil
	}

	// The date is typically in the last part after the semicolon
	datePart := strings.TrimSpace(parts[len(parts)-1])

	return ParseDate(datePart)
}

// ContentType represents email content type information
type ContentType struct {
	MainType string
	SubType  string
	Params   map[string]string
}

// ParseDate parses an RFC 5322 date string from email headers
// Common formats: "Mon, 02 Jan 2006 15:04:05 -0700"
func ParseDate(dateStr string) *time.Time {
	if dateStr == "" {
		return nil
	}

	// RFC 5322 date format (most common in email headers)
	formats := []string{
		time.RFC1123Z,                       // "Mon, 02 Jan 2006 15:04:05 -0700"
		time.RFC1123,                        // "Mon, 02 Jan 2006 15:04:05 MST"
		"Mon, 2 Jan 2006 15:04:05 -0700",    // Single digit day
		"Mon, 2 Jan 2006 15:04:05 MST",      // Single digit day with zone name
		"2 Jan 2006 15:04:05 -0700",         // No day of week
		"2 Jan 2006 15:04:05 MST",           // No day of week with zone name
		"Mon, 02 Jan 2006 15:04:05 -0700 (MST)", // With zone name in parens
		"2 Jan 2006 15:04:05 -0700",         // No day of week, single digit day
		"Mon, 2 Jan 2006 15:04 -0700",       // No seconds
		"2 Jan 2006 15:04 -0700",            // No day of week, no seconds
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return &t
		}
	}

	// If all parsing fails, return nil
	return nil
}
