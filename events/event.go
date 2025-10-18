// Package events provides event models matching the Python ahq_events package
// This is a 100% compatible Go translation for JSON output matching
package events

import (
	"encoding/json"
	"time"
)

// Event represents a parsed abuse event
// This matches the Python ahq_events.event.event.Event class
type Event struct {
	// Core identification fields
	IP               string                 `json:"ip,omitempty"`
	URL              string                 `json:"url,omitempty"`
	Port             int                    `json:"port,omitempty"`
	Domain           string                 `json:"domain,omitempty"`
	ReportID         string                 `json:"report_id,omitempty"`
	Parser           string                 `json:"parser,omitempty"`
	EventTypes       []EventType            `json:"event_types,omitempty"`
	Headers          map[string]interface{} `json:"headers,omitempty"`
	EventDetails     []EventDetail          `json:"event_details,omitempty"`
	Requirements     map[string]Requirement `json:"requirements,omitempty"`
	Error            string                 `json:"error,omitempty"`
	SenderEmail      string                 `json:"sender_email,omitempty"`
	RecipientEmail   string                 `json:"recipient_email,omitempty"`
	ReceivedDate     *time.Time             `json:"received_date,omitempty"`
	SendDate         *time.Time             `json:"send_date,omitempty"`
	EventDate        *time.Time             `json:"event_date,omitempty"`
	ResourcesIncPart []ResourceData         `json:"resources_incident_part,omitempty"`
}

// NewEvent creates a new Event with the specified parser name
func NewEvent(parserName string) *Event {
	return &Event{
		Parser:       parserName,
		Headers:      make(map[string]interface{}),
		Requirements: make(map[string]Requirement),
	}
}

// AddEventDetail adds an event detail to the event
func (e *Event) AddEventDetail(detail EventDetail) {
	e.EventDetails = append(e.EventDetails, detail)
}

// AddEventDetailSimple adds a simple key-value event detail
func (e *Event) AddEventDetailSimple(key string, value interface{}) {
	e.EventDetails = append(e.EventDetails, &SimpleDetail{
		Key:   key,
		Value: value,
	})
}

// AddRequirement adds a requirement to the event
func (e *Event) AddRequirement(key string, req Requirement) {
	if e.Requirements == nil {
		e.Requirements = make(map[string]Requirement)
	}
	e.Requirements[key] = req
}

// RemoveRequirement removes a requirement from the event
func (e *Event) RemoveRequirement(key string) {
	delete(e.Requirements, key)
}

// Validate validates the event meets all requirements
func (e *Event) Validate() error {
	for key, req := range e.Requirements {
		if err := req.Validate(e); err != nil {
			return &RequirementNotMetError{
				RequirementKey: key,
				Cause:          err,
			}
		}
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling
func (e *Event) MarshalJSON() ([]byte, error) {
	// Create an alias to avoid recursion
	type Alias Event
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	})
}

// EventDetail is an interface for event details
type EventDetail interface {
	GetType() string
}

// SimpleDetail represents a simple key-value detail
type SimpleDetail struct {
	Key   string
	Value interface{}
}

func (s *SimpleDetail) GetType() string {
	return "simple"
}

// Sample represents an email sample attachment
type Sample struct {
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
	Description string `json:"description"`
	Payload     string `json:"payload"`
}

func (s *Sample) GetType() string {
	return "sample"
}

// Signature represents a cryptographic signature
type Signature struct {
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"value,omitempty"`
}

func (s *Signature) GetType() string {
	return "signature"
}

// File represents file information
type File struct {
	FileHash string `json:"file_hash,omitempty"`
	FileName string `json:"file_name,omitempty"`
	FileSize string `json:"file_size,omitempty"`
}

func (f *File) GetType() string {
	return "file"
}

// Torrent represents torrent protocol information
type Torrent struct {
	Protocol string `json:"protocol,omitempty"`
	Name     string `json:"name,omitempty"`
	PeerID   string `json:"peer_id,omitempty"`
	Client   string `json:"client,omitempty"`
}

func (t *Torrent) GetType() string {
	return "torrent"
}

// ResourceData represents a key-value resource
type ResourceData struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Target represents attack target information
type Target struct {
	IP      string `json:"ip,omitempty"`
	Port    string `json:"port,omitempty"`
	URL     string `json:"url,omitempty"`
	Service string `json:"service,omitempty"`
	Brand   string `json:"brand,omitempty"`
}

func (t *Target) GetType() string {
	return "target"
}

// HttpRequest represents an HTTP request method
type HttpRequest struct {
	Method string `json:"method,omitempty"`
}

func (h *HttpRequest) GetType() string {
	return "http_request"
}

// ExternalID represents an external tracking ID
type ExternalID struct {
	ID string `json:"id,omitempty"`
}

func (e *ExternalID) GetType() string {
	return "external_id"
}

// ExternalCaseInformation represents external case tracking information
type ExternalCaseInformation struct {
	CaseID   string `json:"case_id,omitempty"`
	Status   string `json:"status,omitempty"`
	Severity string `json:"severity,omitempty"`
}

func (e *ExternalCaseInformation) GetType() string {
	return "external_case_information"
}

// Evidence represents evidence URLs
type Evidence struct {
	URLs []UrlStore `json:"urls,omitempty"`
}

func (e *Evidence) GetType() string {
	return "evidence"
}

// AddEvidence adds a URL to the evidence
func (e *Evidence) AddEvidence(url UrlStore) {
	e.URLs = append(e.URLs, url)
}

// UrlStore represents a stored URL
type UrlStore struct {
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}

// OnBehalfOf represents complaint contact information
type OnBehalfOf struct {
	ComplainantContact string `json:"complainant_contact,omitempty"`
	ComplainantEmail   string `json:"complainant_email,omitempty"`
}

func (o *OnBehalfOf) GetType() string {
	return "on_behalf_of"
}

// Password represents password/credentials information
type Password struct {
	PasswordHash  string `json:"password_hash,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

func (p *Password) GetType() string {
	return "password"
}

// ISP represents ISP information
type ISP struct {
	ISPName string `json:"isp_name,omitempty"`
	Country string `json:"country,omitempty"`
}

func (i *ISP) GetType() string {
	return "isp"
}

// ASN represents an Autonomous System Number
type ASN struct {
	ASN    string `json:"asn,omitempty"`
	ASName string `json:"as_name,omitempty"`
}

func (a *ASN) GetType() string {
	return "asn"
}

// Location represents geolocation information
type Location struct {
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
}

func (l *Location) GetType() string {
	return "location"
}

// TransportProtocol represents a network transport protocol
type TransportProtocol struct {
	Protocol string `json:"protocol,omitempty"`
}

func (t *TransportProtocol) GetType() string {
	return "transport_protocol"
}

// Organisation represents organization/reporter information
type Organisation struct {
	Name         string `json:"name,omitempty"`
	Organisation string `json:"organisation,omitempty"`
	ContactName  string `json:"contact_name,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	ContactPhone string `json:"contact_phone,omitempty"`
	Address      string `json:"address,omitempty"`
	URLOrDomain  string `json:"url_or_domain,omitempty"`
}

func (o *Organisation) GetType() string {
	return "organisation"
}

// CommandAndControl represents C&C server information
type CommandAndControl struct {
	URL  string `json:"url,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port string `json:"port,omitempty"`
}

func (c *CommandAndControl) GetType() string {
	return "command_and_control"
}

// NAICS represents North American Industry Classification System code
type NAICS struct {
	NAICS string `json:"naics,omitempty"`
}

func (n *NAICS) GetType() string {
	return "naics"
}

// TrafficStats represents network traffic statistics
type TrafficStats struct {
	PacketCount int `json:"packet_count,omitempty"`
	ByteCount   int `json:"byte_count,omitempty"`
}

func (t *TrafficStats) GetType() string {
	return "traffic_stats"
}

// DateTime represents a datetime string wrapper
type DateTime struct {
	Value string
}

// NewDateTime creates a new DateTime wrapper
func NewDateTime(value string) *DateTime {
	return &DateTime{Value: value}
}

// SPF represents SPF authentication result detail
type SPF struct {
	Domain string `json:"domain,omitempty"`
	Result string `json:"result,omitempty"`
}

func (s *SPF) GetType() string {
	return "spf"
}

// DKIM represents DKIM authentication result detail
type DKIM struct {
	Domain string `json:"domain,omitempty"`
	Result string `json:"result,omitempty"`
}

func (d *DKIM) GetType() string {
	return "dkim"
}

// Email represents email-related event detail
type Email struct {
	FromAddress string `json:"from_address,omitempty"`
	ToAddress   string `json:"to_address,omitempty"`
	Subject     string `json:"subject,omitempty"`
}

func (e *Email) GetType() string {
	return "email"
}

// SpammerMails represents a list of spammer email addresses
type SpammerMails struct {
	Addresses []string `json:"addresses,omitempty"`
}

func (s *SpammerMails) GetType() string {
	return "spammer_mails"
}

// RequirementNotMetError is raised when event validation fails
type RequirementNotMetError struct {
	RequirementKey string
	Cause          error
}

func (e *RequirementNotMetError) Error() string {
	if e.Cause != nil {
		return "requirement '" + e.RequirementKey + "' not met: " + e.Cause.Error()
	}
	return "requirement '" + e.RequirementKey + "' not met"
}

func (e *RequirementNotMetError) Unwrap() error {
	return e.Cause
}
