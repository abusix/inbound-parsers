// Package common provides archive handling utilities
package common

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/abusix/inbound-parsers/pkg/email"
)

// HandleZipPart extracts and returns the first file from a ZIP attachment
func HandleZipPart(body interface{}) (string, error) {
	var zipData []byte

	switch b := body.(type) {
	case string:
		zipData = []byte(b)
	case []byte:
		zipData = b
	default:
		return "", fmt.Errorf("unexpected body type: %T", body)
	}

	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return "", fmt.Errorf("failed to open ZIP: %w", err)
	}

	if len(reader.File) == 0 {
		return "", fmt.Errorf("ZIP file is empty")
	}

	// Extract the first file
	f := reader.File[0]
	rc, err := f.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open file in ZIP: %w", err)
	}
	defer rc.Close()

	content, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("failed to read file from ZIP: %w", err)
	}

	return string(content), nil
}

// ExtractCSVFromEmail extracts CSV content from email parts
func ExtractCSVFromEmail(serializedEmail *email.SerializedEmail) (string, error) {
	if len(serializedEmail.Parts) < 2 {
		return "", NewParserError("CSV attachment not found")
	}

	part := serializedEmail.Parts[1]

	// Check content type in headers
	var contentType string
	if part.Headers != nil {
		if ct, ok := part.Headers["content-type"]; ok && len(ct) > 0 {
			contentType = strings.ToLower(ct[0])
		}
	}
	// Fallback to part.ContentType
	if contentType == "" {
		contentType = strings.ToLower(part.ContentType)
	}

	var csvFile string
	var err error

	if strings.Contains(contentType, "zip") {
		csvFile, err = HandleZipPart(part.Body)
		if err != nil {
			return "", err
		}
	} else if strings.Contains(contentType, "csv") {
		switch body := part.Body.(type) {
		case string:
			csvFile = body
		case []byte:
			csvFile = string(body)
		default:
			return "", NewParserError("unexpected CSV body type")
		}
	} else {
		return "", NewParserError("CSV attachment not found")
	}

	// Replace spaces with underscores
	csvFile = strings.ReplaceAll(csvFile, " ", "_")

	return csvFile, nil
}
