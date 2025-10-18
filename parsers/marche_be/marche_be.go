package marche_be

import (
	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

// Parse - TODO: Implement marche_be parser (no Python source available)
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	return nil, common.NewIgnoreError("marche_be parser not implemented")
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 100 // Default vendor parser priority
}
