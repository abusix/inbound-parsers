package csirt_dnofd

import (
	"testing"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
)

func TestParsePhishing(t *testing.T) {
	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"#71706538 Phishing hosted at your site (autobrasilgerenciadorempresarial[.]com->191[.]96[.]56[.]3)"},
			"date":    {"Tue, 27 Sep 2022 14:15:58 -0300"},
		},
		Body: `Dear Sir/Madam,

We are Topaz OFD - Anti-Fraud Intelligence.

You've received this message because you are the WHOIS contact for the
network mentioned below. This message is intended for the person
responsible for computer security at your site. If this is not the
correct address, please forward this message to the appropriate party.

We detected a phishing web site at 2022-09-27T17:05:27.693939+00:00 hosted at:

    * http[:]//autobrasilgerenciadorempresarial[.]com/Brasil/acesso-conta-pc.php
    * autobrasilgerenciadorempresarial[.]com with ip 191[.]96[.]56[.]3

That redirect to:

    * https[:]//autobrasilgerenciadorempresarial[.]com/Brasil/acesso-conta-pc.php

This is a fake website pretending to be Banco do Brasil website
with the intent of committing fraud against the organization and/or
its users. The organization's legitimate website is:

    https[:]//www[.]bb[.]com[.]br/


We kindly ask your cooperation, according to your policies:

    * to cease this activity and shut down the phishing page;

    * sending us any logs or other information regarding the access to
      this homepage;

    * sending us the phishing website files;

    * also, if in the course of your analyses you can determine where
      the data collected is being sent, please send us this
      information. It could help us in our analysis.


    Thanks in advance. We would also appreciate a reply that this message
    has been received.


Best regards,
CSIRT.`,
	}

	parser := NewParser()
	result, err := parser.Parse(serializedEmail)

	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(result))
	}

	event := result[0]

	// Check IP extraction
	if event.IP != "191.96.56.3" {
		t.Errorf("Expected IP '191.96.56.3', got '%s'", event.IP)
	}

	// Check URL extraction
	expectedURL := "http://autobrasilgerenciadorempresarial.com/Brasil/acesso-conta-pc.php"
	if event.URL != expectedURL {
		t.Errorf("Expected URL '%s', got '%s'", expectedURL, event.URL)
	}

	// Check event type
	if len(event.EventTypes) != 1 {
		t.Fatalf("Expected 1 event type, got %d", len(event.EventTypes))
	}

	phishing, ok := event.EventTypes[0].(*events.Phishing)
	if !ok {
		t.Fatalf("Expected Phishing event type, got %T", event.EventTypes[0])
	}

	// Check official URL
	expectedOfficialURL := "https://www.bb.com.br/"
	if phishing.OfficialURL != expectedOfficialURL {
		t.Errorf("Expected official URL '%s', got '%s'", expectedOfficialURL, phishing.OfficialURL)
	}

	// Check event date
	if event.EventDate == nil {
		t.Error("Expected event date to be set")
	}
}

func TestParsePhishingNoIPOrURL(t *testing.T) {
	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Phishing report"},
			"date":    {"Tue, 27 Sep 2022 14:15:58 -0300"},
		},
		Body: `We detected a phishing web site at 2022-09-27T17:05:27.693939+00:00 hosted at:`,
	}

	parser := NewParser()
	_, err := parser.Parse(serializedEmail)

	if err == nil {
		t.Error("Expected error for phishing report without IP or URL")
	}
}

func TestParseNonPhishing(t *testing.T) {
	serializedEmail := &email.SerializedEmail{
		Headers: map[string][]string{
			"subject": {"Some other abuse report"},
			"date":    {"Tue, 27 Sep 2022 14:15:58 -0300"},
		},
		Body: "This is not a phishing report",
	}

	parser := NewParser()
	_, err := parser.Parse(serializedEmail)

	if err == nil {
		t.Error("Expected NewTypeError for non-phishing subject")
	}
}
