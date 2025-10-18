// Package events provides requirement validation
package events

import "fmt"

// Requirement is an interface for event validation requirements
type Requirement interface {
	Validate(event *Event) error
}

// AndRequirement validates that all sub-requirements are met
type AndRequirement struct {
	Requirements []interface{}
}

// NewAndRequirement creates a new AND requirement
func NewAndRequirement(requirements []interface{}) *AndRequirement {
	return &AndRequirement{
		Requirements: requirements,
	}
}

// Validate checks that all requirements are met
func (a *AndRequirement) Validate(event *Event) error {
	for i, req := range a.Requirements {
		// Check if it's a field name (string)
		if fieldName, ok := req.(string); ok {
			// Validate that the field exists and is not empty
			if !hasNonEmptyField(event, fieldName) {
				return fmt.Errorf("requirement %d: field '%s' is empty or missing", i, fieldName)
			}
		} else if subReq, ok := req.(Requirement); ok {
			// It's a nested requirement
			if err := subReq.Validate(event); err != nil {
				return fmt.Errorf("requirement %d: %w", i, err)
			}
		} else {
			return fmt.Errorf("requirement %d: invalid requirement type", i)
		}
	}
	return nil
}

// OrRequirement validates that at least one sub-requirement is met
type OrRequirement struct {
	Requirements []interface{}
}

// NewOrRequirement creates a new OR requirement
func NewOrRequirement(requirements []interface{}) *OrRequirement {
	return &OrRequirement{
		Requirements: requirements,
	}
}

// Validate checks that at least one requirement is met
func (o *OrRequirement) Validate(event *Event) error {
	var errors []error

	for i, req := range o.Requirements {
		// Check if it's a field name (string)
		if fieldName, ok := req.(string); ok {
			// Validate that the field exists and is not empty
			if hasNonEmptyField(event, fieldName) {
				return nil // At least one is satisfied
			}
			errors = append(errors, fmt.Errorf("field '%s' is empty or missing", fieldName))
		} else if subReq, ok := req.(Requirement); ok {
			// It's a nested requirement
			if err := subReq.Validate(event); err == nil {
				return nil // At least one is satisfied
			} else {
				errors = append(errors, err)
			}
		} else {
			return fmt.Errorf("requirement %d: invalid requirement type", i)
		}
	}

	// None of the requirements were met
	return fmt.Errorf("none of the OR requirements were met: %v", errors)
}

// hasNonEmptyField checks if an event has a non-empty field
func hasNonEmptyField(event *Event, fieldName string) bool {
	switch fieldName {
	case "ip":
		return event.IP != ""
	case "url":
		return event.URL != ""
	case "domain":
		return event.Domain != ""
	case "port":
		return event.Port != 0
	case "headers":
		return len(event.Headers) > 0
	case "event_types":
		return len(event.EventTypes) > 0
	default:
		return false
	}
}
