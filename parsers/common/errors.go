// Package common provides common parser utilities and error types
package common

import "fmt"

// ParserError represents a general parsing error
type ParserError struct {
	Message string
}

func (e *ParserError) Error() string {
	return fmt.Sprintf("parser error: %s", e.Message)
}

// NewParserError creates a new ParserError
func NewParserError(message string) *ParserError {
	return &ParserError{Message: message}
}

// NewTypeError represents an error when encountering unknown event types
type NewTypeError struct {
	Subject string
}

func (e *NewTypeError) Error() string {
	return fmt.Sprintf("unknown type in subject: %s", e.Subject)
}

// NewNewTypeError creates a new NewTypeError
func NewNewTypeError(subject string) *NewTypeError {
	return &NewTypeError{Subject: subject}
}

// RejectError indicates that an email should be rejected (not processed)
type RejectError struct {
	Reason string
}

func (e *RejectError) Error() string {
	return fmt.Sprintf("email rejected: %s", e.Reason)
}

// NewRejectError creates a new RejectError
func NewRejectError(reason string) *RejectError {
	return &RejectError{Reason: reason}
}

// IgnoreError indicates that an email should be ignored (not processed)
type IgnoreError struct {
	Reason string
}

func (e *IgnoreError) Error() string {
	return fmt.Sprintf("email ignored: %s", e.Reason)
}

// NewIgnoreError creates a new IgnoreError
func NewIgnoreError(reason string) *IgnoreError {
	return &IgnoreError{Reason: reason}
}
