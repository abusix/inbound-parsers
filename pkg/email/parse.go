package email

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
)

// Parse parses a raw email into a SerializedEmail struct
func Parse(rawEmail []byte) (*SerializedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(rawEmail))
	if err != nil {
		return nil, err
	}

	serialized := &SerializedEmail{
		Headers: make(map[string][]string),
		Parts:   []EmailPart{},
	}

	// Parse headers
	for key, values := range msg.Header {
		lowerKey := strings.ToLower(key)
		serialized.Headers[lowerKey] = values
	}

	// Get content type
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
		params = make(map[string]string)
	}

	// Check if multipart
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary != "" {
			parts, err := parseMultipart(msg.Body, boundary)
			if err == nil {
				serialized.Parts = parts
			}
		}
	} else {
		// Single part email
		body, err := io.ReadAll(msg.Body)
		if err == nil {
			part := EmailPart{
				ContentType: mediaType,
				Body:        decodeBody(body, msg.Header.Get("Content-Transfer-Encoding")),
			}
			serialized.Parts = []EmailPart{part}
		}
	}

	return serialized, nil
}

func parseMultipart(body io.Reader, boundary string) ([]EmailPart, error) {
	var parts []EmailPart
	mr := multipart.NewReader(body, boundary)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return parts, err
		}

		contentType := part.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "text/plain"
		}

		mediaType, params, _ := mime.ParseMediaType(contentType)

		partBody, err := io.ReadAll(part)
		if err != nil {
			continue
		}

		encoding := part.Header.Get("Content-Transfer-Encoding")
		decodedBody := decodeBody(partBody, encoding)

		emailPart := EmailPart{
			ContentType: mediaType,
			Body:        decodedBody,
		}

		// Handle nested multipart
		if strings.HasPrefix(mediaType, "multipart/") {
			if nestedBoundary := params["boundary"]; nestedBoundary != "" {
				nestedParts, err := parseMultipart(bytes.NewReader(decodedBody), nestedBoundary)
				if err == nil {
					emailPart.Parts = nestedParts
				}
			}
		}

		parts = append(parts, emailPart)
	}

	return parts, nil
}

func decodeBody(body []byte, encoding string) []byte {
	encoding = strings.ToLower(strings.TrimSpace(encoding))

	switch encoding {
	case "base64":
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
		n, err := base64.StdEncoding.Decode(decoded, body)
		if err == nil {
			return decoded[:n]
		}
	case "quoted-printable":
		reader := quotedprintable.NewReader(bytes.NewReader(body))
		decoded, err := io.ReadAll(reader)
		if err == nil {
			return decoded
		}
	}

	return body
}
