// Package common provides URL utility functions
package common

import (
	"net/url"
	"strings"
)

// IsURL checks if a string is a valid URL
func IsURL(data string) bool {
	data = strings.TrimSpace(data)
	if data == "" {
		return false
	}

	// Must start with http:// or https://
	if !strings.HasPrefix(data, "http://") && !strings.HasPrefix(data, "https://") {
		return false
	}

	_, err := url.Parse(data)
	return err == nil
}

// ProcessURL processes and validates a URL (similar to UrlStore.process_url)
func ProcessURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", &ParserError{Message: "Empty URL"}
	}

	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	if u.Host == "" {
		return "", &ParserError{Message: "Invalid URL: no host"}
	}

	return u.String(), nil
}

// GetBlockAfterWithStop extracts a block of non-empty lines after a marker
// If stopMarker is empty, continues until end
func GetBlockAfterWithStop(base, startMarker, stopMarker string) []string {
	startIdx := strings.Index(base, startMarker)
	if startIdx == -1 {
		return nil
	}

	text := base[startIdx+len(startMarker):]

	if stopMarker != "" {
		endIdx := strings.Index(text, stopMarker)
		if endIdx != -1 {
			text = text[:endIdx]
		}
	}

	var result []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}

	return result
}
