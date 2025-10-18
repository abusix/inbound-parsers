package simple_rewrite

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
)

// Parser handles Google Groups mailing list rewrites
// When Google Groups rewrites the FROM address, it moves the original sender to X-Original-Sender
type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Match checks if this email should be rewritten
// Returns true if:
// - from_addr exists
// - x-original-sender header exists
// - from_addr appears in list-post header
// - from_addr does NOT appear in x-original-sender
func Match(serializedEmail *email.SerializedEmail, fromAddr string) bool {
	if fromAddr == "" {
		return false
	}

	if serializedEmail.Headers == nil {
		return false
	}

	// Check for x-original-sender header
	xOriginalSender, hasXOriginal := serializedEmail.Headers["x-original-sender"]
	if !hasXOriginal || len(xOriginalSender) == 0 {
		return false
	}

	// Check if from_addr appears in list-post header
	listPost, hasListPost := serializedEmail.Headers["list-post"]
	if !hasListPost {
		return false
	}

	foundInListPost := false
	for _, post := range listPost {
		if strings.Contains(post, fromAddr) {
			foundInListPost = true
			break
		}
	}

	if !foundInListPost {
		return false
	}

	// Check that from_addr does NOT appear in x-original-sender
	if strings.Contains(xOriginalSender[0], fromAddr) {
		return false
	}

	return true
}

// Rewrite extracts the new from_addr from x-original-sender header
func Rewrite(serializedEmail *email.SerializedEmail) (string, error) {
	if serializedEmail.Headers == nil {
		return "", fmt.Errorf("rewrite was called, but no headers found")
	}

	xOriginalSender, hasXOriginal := serializedEmail.Headers["x-original-sender"]
	if !hasXOriginal || len(xOriginalSender) == 0 {
		return "", fmt.Errorf("rewrite was called, but no logic matched")
	}

	// Parse the email address from the header
	// Format could be "Name <email@example.com>" or just "email@example.com"
	addr, err := mail.ParseAddress(xOriginalSender[0])
	if err != nil {
		// If parsing fails, try to extract just the email part
		return extractEmailAddress(xOriginalSender[0]), nil
	}

	return strings.ToLower(addr.Address), nil
}

// extractEmailAddress extracts email address from a string
func extractEmailAddress(s string) string {
	s = strings.TrimSpace(s)

	// Check for <email@example.com> format
	if startIdx := strings.Index(s, "<"); startIdx != -1 {
		if endIdx := strings.Index(s[startIdx:], ">"); endIdx != -1 {
			return strings.ToLower(strings.TrimSpace(s[startIdx+1 : startIdx+endIdx]))
		}
	}

	// Return as-is if no brackets found
	return strings.ToLower(strings.TrimSpace(s))
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 2
}
