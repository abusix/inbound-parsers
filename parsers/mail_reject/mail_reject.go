package mail_reject

import (
	"regexp"
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/common"
	"github.com/abusix/inbound-parsers/pkg/email"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse implements a matcher/filter parser that returns RejectError or IgnoreError
// instead of generating events. This parser identifies and rejects known non-abuse emails.
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	fromAddr, err := common.GetFrom(serializedEmail, false)
	if err != nil || fromAddr == "" {
		return nil, common.NewIgnoreError("no from address")
	}

	subject, _ := common.GetSubject(serializedEmail, false)
	subjectLower := strings.ToLower(subject)

	body, _ := common.GetBody(serializedEmail, false)
	bodyLower := strings.ToLower(body)

	// Check each rejection rule
	if strings.Contains(fromAddr, "@mg.abuseipdb") {
		if containsAny(bodyLower, []string{"was approved", "was denied"}) {
			return nil, common.NewRejectError("abuseipdb status notification")
		}
	}

	if fromAddr == "support@checkdomain.de" {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("checkdomain reply")
		}
	}

	if strings.Contains(fromAddr, "@inap.com") {
		if containsAny(subjectLower, []string{"resolved", "closed", "proposed", "comments added"}) {
			return nil, common.NewRejectError("inap ticket status")
		}
	}

	if fromAddr == "thomaslichtenstein@gmail.com" {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("personal reply")
		}
	}

	if strings.Contains(fromAddr, "@privateinternetaccess.com") {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("pia reply")
		}
	}

	if fromAddr == "takeda.ipr@ybrandprotection.com" {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("ybrand reply")
		}
	}

	if strings.Contains(fromAddr, "@ufabc.edu.br") {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("ufabc reply")
		}
	}

	if fromAddr == "postmaster@wisctest.wisc.edu" {
		return nil, common.NewRejectError("wisc postmaster")
	}

	if strings.Contains(fromAddr, "postmaster@") {
		if strings.Contains(subjectLower, "message couldn't be delivered") {
			return nil, common.NewRejectError("delivery failure")
		}
	}

	if fromAddr == "israel@idn.com.do" {
		return nil, common.NewRejectError("idn spam")
	}

	if strings.Contains(fromAddr, "@cyberghost.ro") {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("cyberghost reply")
		}
	}

	if strings.Contains(fromAddr, "@linode.com") {
		if strings.Contains(bodyLower, "response from abusix") {
			return nil, common.NewRejectError("linode web form")
		}

		// Check x-original-sender header
		if headers := serializedEmail.Headers; headers != nil {
			if xOrigSender, ok := headers["x-original-sender"]; ok && len(xOrigSender) > 0 {
				if !strings.Contains(xOrigSender[0], "@linode.com") {
					return nil, common.NewIgnoreError("linode forwarded email")
				}
			}
		}

		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("linode reply")
		}

		// Check received headers for abuse@linode.com
		if headers := serializedEmail.Headers; headers != nil {
			if received, ok := headers["received"]; ok {
				for _, r := range received {
					if strings.Contains(r, "for <abuse@linode.com>") {
						return nil, common.NewRejectError("linode internal")
					}
				}
			}
		}
	}

	if strings.Contains(fromAddr, "@windstream.net") {
		if subjectLower == "" {
			return nil, common.NewRejectError("windstream empty subject")
		}
		if containsAny(subjectLower, []string{"mail delivery failure", "fwd:", "fw:"}) {
			return nil, common.NewRejectError("windstream forward/bounce")
		}
	}

	if strings.Contains(fromAddr, "@digitalocean.com") {
		if containsAny(bodyLower, []string{"for your report", "for submitting", "for bringing this to our attention"}) {
			return nil, common.NewRejectError("digitalocean acknowledgment")
		}
	}

	if strings.Contains(fromAddr, "@lctech.com.tw") {
		return nil, common.NewRejectError("lctech spam")
	}

	if fromAddr == "dmca@maxcdn.com" {
		return nil, common.NewRejectError("maxcdn dmca")
	}

	if fromAddr == "support@cloudbric.com" {
		if strings.Contains(subjectLower, "monthly summarized report") {
			return nil, common.NewRejectError("cloudbric summary")
		}
	}

	if strings.HasSuffix(fromAddr, ".govdelivery.com") {
		return nil, common.NewRejectError("govdelivery newsletter")
	}

	if fromAddr == "admin@layerish.net" {
		if strings.Contains(subjectLower, "re:") {
			return nil, common.NewRejectError("layerish reply")
		}
	}

	if fromAddr == "netops@rockionllc.com" {
		return nil, common.NewRejectError("rockion spam")
	}

	if fromAddr == "posta-certificata@legalmail.it" {
		return nil, common.NewRejectError("italian certified mail")
	}

	if strings.Contains(fromAddr, "team@tier.net") {
		if strings.Contains(bodyLower, "ticket has now been opened") {
			return nil, common.NewRejectError("tier ticket opened")
		}
		if containsAny(bodyLower, []string{"status: answered", "status: closed"}) {
			return nil, common.NewRejectError("tier ticket status")
		}
	}

	if fromAddr == "abuse@contabo.com" {
		if strings.Contains(subjectLower, "abuse complaint resolved") ||
			strings.Contains(bodyLower, "we have opened a case and contacted our customer") {
			return nil, common.NewRejectError("contabo acknowledgment")
		}
	}

	if fromAddr == "v.billoudet@idetop.com" {
		if strings.Contains(subjectLower, "will be suspended temporarily to secure your account") {
			return nil, common.NewRejectError("idetop phishing")
		}
	}

	deftAddresses := []string{
		"jhastings@deft.com",
		"abuse@deft.com",
		"dmca@deft.com",
		"support@deft.com",
		"alatzko@deft.com",
	}
	if containsAny(fromAddr, deftAddresses) {
		return nil, common.NewRejectError("deft email")
	}

	if fromAddr == "chris.schukar@savealot.com" {
		return nil, common.NewRejectError("savealot spam")
	}

	if fromAddr == "noreply@notify.cloudflare.com" && strings.Contains(subjectLower, "abuse report") {
		return nil, common.NewRejectError("cloudflare notification")
	}

	if fromAddr == "mailer-daemon@fireeyecloud.com" && strings.Contains(subjectLower, "mail delivery failure") {
		return nil, common.NewRejectError("fireeye bounce")
	}

	if strings.Contains(fromAddr, "@infinitycds.co.za") {
		return nil, common.NewRejectError("infinitycds spam")
	}

	if fromAddr == "newsletter@brainpickings.org" {
		return nil, common.NewRejectError("brainpickings newsletter")
	}

	if fromAddr == "support@internetvikings.com" {
		return nil, common.NewRejectError("internetvikings spam")
	}

	if fromAddr == "abuse@mochahost.com" {
		if strings.Contains(subjectLower, "re:") || strings.Contains(subjectLower, "ticket opened") {
			return nil, common.NewRejectError("mochahost ticket")
		}
	}

	if fromAddr == "newsletter@someecards.com" {
		return nil, common.NewRejectError("someecards newsletter")
	}

	if fromAddr == "mail@messaging.zoosk.com" {
		return nil, common.NewRejectError("zoosk spam")
	}

	if strings.Contains(fromAddr, "newsletters.scrippsweb.com") {
		return nil, common.NewRejectError("scripps newsletter")
	}

	if strings.Contains(fromAddr, "newsletters@wbur.org") {
		return nil, common.NewRejectError("wbur newsletter")
	}

	if strings.Contains(fromAddr, "support@vultr.com") {
		if strings.Contains(subjectLower, "announcement validation") ||
			strings.Contains(bodyLower, "our support team will review") {
			return nil, common.NewRejectError("vultr notification")
		}
	}

	if strings.Contains(fromAddr, "newsletter@pattayamail.com") {
		return nil, common.NewRejectError("pattayamail newsletter")
	}

	if strings.Contains(fromAddr, "root@mx.srhosting.eu") {
		return nil, common.NewRejectError("srhosting empty")
	}

	if strings.Contains(fromAddr, "@afrinic.net") {
		return nil, common.NewRejectError("afrinic spam")
	}

	if strings.Contains(fromAddr, "info@n.lookfantastic.com") {
		return nil, common.NewRejectError("lookfantastic newsletter")
	}

	eastlinkAddresses := []string{
		"ireneandtomrose@eastlink.ca",
		"harrietmccready@eastlink.ca",
		"robsonbh@eastlink.ca",
	}
	if containsAny(fromAddr, eastlinkAddresses) {
		if containsAny(subjectLower, []string{"fwd:", "fw:"}) {
			return nil, common.NewRejectError("eastlink forward")
		}
	}

	if strings.Contains(fromAddr, "@inap.com") && strings.Contains(strings.ToLower(subject), "comments added - re:") {
		return nil, common.NewRejectError("inap comments")
	}

	if strings.Contains(fromAddr, "@losangelesblade.com") {
		return nil, common.NewRejectError("losangelesblade newsletter")
	}

	if strings.Contains(fromAddr, "informationloanfirm@consultant.com") {
		return nil, common.NewRejectError("loan spam")
	}

	if strings.Contains(fromAddr, "abuse@support.gandi.net") {
		return nil, common.NewRejectError("gandi spam")
	}

	if fromAddr == "abuse@latitude.sh" {
		serviceQualityPattern := regexp.MustCompile(`Request #\d+: How would you rate the support you received\?`)
		if strings.HasPrefix(strings.ToLower(subject), "[latitude.sh] re:") {
			return nil, common.NewRejectError("latitude reply")
		}
		if strings.HasPrefix(strings.ToLower(subject), "[request received]") {
			return nil, common.NewRejectError("latitude request received")
		}
		if serviceQualityPattern.MatchString(subject) {
			return nil, common.NewRejectError("latitude survey")
		}
	}

	if strings.Contains(fromAddr, "@spotify.com") {
		spotifyPrefixes := []string{"no-reply", "help", "support"}
		for _, prefix := range spotifyPrefixes {
			if strings.Contains(fromAddr, prefix) {
				return nil, common.NewRejectError("spotify notification")
			}
		}
	}

	if strings.Contains(fromAddr, "abuse@mailchimp.zendesk.com") {
		if containsAny(subjectLower, []string{"your mailchimp support request", "re:"}) {
			return nil, common.NewRejectError("mailchimp support")
		}
	}

	if strings.Contains(fromAddr, "noreply@lacnic.net") {
		return nil, common.NewRejectError("lacnic notification")
	}

	if strings.Contains(fromAddr, "mail@netcup.de") {
		return nil, common.NewRejectError("netcup spam")
	}

	if strings.Contains(fromAddr, "onlineorders@hertex.co.za") {
		return nil, common.NewRejectError("hertex spam")
	}

	if strings.Contains(fromAddr, "abuse@openprovider.nl") && strings.Contains(subjectLower, "rate the support you received") {
		return nil, common.NewRejectError("openprovider survey")
	}

	if strings.Contains(fromAddr, "abuse@corp1.zendesk.com") {
		return nil, common.NewRejectError("zendesk spam")
	}

	if strings.Contains(fromAddr, "registry-abuse-support@google.com") {
		return nil, common.NewRejectError("google registry")
	}

	// If no rule matched, return IgnoreError (continue processing)
	return nil, common.NewIgnoreError("no rejection rule matched")
}

// containsAny checks if s contains any of the substrings in needles
func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 1
}
