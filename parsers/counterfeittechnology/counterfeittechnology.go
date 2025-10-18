package counterfeittechnology

import (
	"fmt"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	// Get email body - throw error if missing
	body, err := common.GetBody(serializedEmail, true)
	if err != nil {
		return nil, err
	}

	// Create event
	event := events.NewEvent("counterfeittechnology")

	// Set event_date from headers['date'][0]
	if serializedEmail.Headers != nil {
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			event.EventDate = email.ParseDate(dateHeaders[0])
		}
	}

	// Extract copyright owner
	// Python: start_index_owner = body.find('owned by') + len('owned by')
	//         end_index_owner = body.find('The website', start_index_owner)
	//         owner = body[start_index_owner:end_index_owner].strip('\n\r. \u00a0')
	startMarker := "owned by"
	endMarker := "The website"
	startIdx := strings.Index(body, startMarker)
	if startIdx == -1 {
		return nil, fmt.Errorf("could not find copyright owner marker 'owned by'")
	}
	startIdx += len(startMarker)
	remaining := body[startIdx:]
	endIdx := strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return nil, fmt.Errorf("could not find copyright owner end marker 'The website'")
	}
	owner := strings.Trim(remaining[:endIdx], "\n\r. \u00a0")
	owner = strings.TrimSpace(owner)

	// Extract copyrighted work URL (official_url)
	// Python: start_index_copyrighted_work_url = body.find('can be found at:') + len('can be found at:')
	//         end_index_copyrighted_work_url = body.find('Please allow', start_index_copyrighted_work_url)
	//         copyrighted_work_url = body[start_index_copyrighted_work_url:end_index_copyrighted_work_url].strip('\n\r. \u00a0')
	startMarker = "can be found at:"
	endMarker = "Please allow"
	startIdx = strings.Index(body, startMarker)
	if startIdx == -1 {
		return nil, fmt.Errorf("could not find official URL marker 'can be found at:'")
	}
	startIdx += len(startMarker)
	remaining = body[startIdx:]
	endIdx = strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return nil, fmt.Errorf("could not find official URL end marker 'Please allow'")
	}
	officialURL := strings.Trim(remaining[:endIdx], "\n\r. \u00a0")
	officialURL = strings.TrimSpace(officialURL)

	// Extract infringing URL
	// Python: start_index_infringing_url = body.find('can be found here:') + len('can be found here:')
	//         end_index_infringing_url = body.find('The unauthorized', start_index_infringing_url)
	//         infringing_url = body[start_index_infringing_url:end_index_infringing_url].strip('\n\r. \u00a0')
	//         event.url = infringing_url
	startMarker = "can be found here:"
	endMarker = "The unauthorized"
	startIdx = strings.Index(body, startMarker)
	if startIdx == -1 {
		return nil, fmt.Errorf("could not find infringing URL marker 'can be found here:'")
	}
	startIdx += len(startMarker)
	remaining = body[startIdx:]
	endIdx = strings.Index(remaining, endMarker)
	if endIdx == -1 {
		return nil, fmt.Errorf("could not find infringing URL end marker 'The unauthorized'")
	}
	infringingURL := strings.Trim(remaining[:endIdx], "\n\r. \u00a0")
	infringingURL = strings.TrimSpace(infringingURL)
	event.URL = infringingURL

	// Create copyright event type with extracted data
	copyright := events.NewCopyright("", owner, "")
	copyright.OfficialURL = officialURL
	event.EventTypes = []events.EventType{copyright}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
