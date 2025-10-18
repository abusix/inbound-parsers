// Package common provides IP address utilities
package common

import (
	"net"
	"regexp"
	"strings"
)

var (
	ipRegex    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
)

// ExtractOneIP extracts the first IP address from a string
func ExtractOneIP(text string) string {
	// Clean up common obfuscations
	text = strings.ReplaceAll(text, "[.]", ".")
	text = strings.ReplaceAll(text, "[", "")
	text = strings.ReplaceAll(text, "]", "")

	match := ipRegex.FindString(text)
	if match != "" {
		// Validate it's a real IP
		if net.ParseIP(match) != nil {
			return match
		}
	}
	return ""
}

// IsIP checks if a string is a valid IP address
func IsIP(ipStr string) string {
	// Clean up common obfuscations
	ipStr = strings.ReplaceAll(ipStr, "[.]", ".")
	ipStr = strings.ReplaceAll(ipStr, "[", "")
	ipStr = strings.ReplaceAll(ipStr, "]", "")
	ipStr = strings.TrimSpace(ipStr)

	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}

// ExtractAllIPv4 extracts all IPv4 addresses from a string
func ExtractAllIPv4(text string) []string {
	// Clean up common obfuscations
	text = strings.ReplaceAll(text, "[.]", ".")
	text = strings.ReplaceAll(text, "[", "")
	text = strings.ReplaceAll(text, "]", "")

	matches := ipRegex.FindAllString(text, -1)
	var validIPs []string

	for _, match := range matches {
		// Validate it's a real IP
		if net.ParseIP(match) != nil {
			validIPs = append(validIPs, match)
		}
	}

	return validIPs
}

// ExtractOneEmail extracts the first email address from a string
func ExtractOneEmail(text string) string {
	match := emailRegex.FindString(text)
	return match
}
