// Package common provides report structures for parser output
package common

import "github.com/abusix/inbound-parsers/events"

// Report represents the result of parsing an email
type Report struct {
	Events []*events.Event `json:"events"`
}

// NewReport creates a new Report
func NewReport() *Report {
	return &Report{
		Events: make([]*events.Event, 0),
	}
}

// AddEvent adds an event to the report
func (r *Report) AddEvent(event *events.Event) {
	r.Events = append(r.Events, event)
}
