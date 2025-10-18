// Package events provides event type definitions
package events

// EventType is an interface for all event types
type EventType interface {
	GetName() string
	GetType() string
}

// BaseEventType provides common fields for event types
type BaseEventType struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

func (b *BaseEventType) GetName() string {
	return b.Name
}

func (b *BaseEventType) GetType() string {
	return b.Type
}

// Spam represents a spam event type
type Spam struct {
	BaseEventType
}

// NewSpam creates a new Spam event type
func NewSpam() *Spam {
	return &Spam{
		BaseEventType: BaseEventType{
			Name: "spam",
			Type: "spam",
		},
	}
}

// Phishing represents a phishing event type
type Phishing struct {
	BaseEventType
	PhishingTarget string `json:"phishing_target,omitempty"`
	OfficialURL    string `json:"official_url,omitempty"`
}

// NewPhishing creates a new Phishing event type
func NewPhishing() *Phishing {
	return &Phishing{
		BaseEventType: BaseEventType{
			Name: "phishing",
			Type: "phishing",
		},
	}
}

// NewPhishingWithOfficialURL creates a new Phishing event type with official URL
func NewPhishingWithOfficialURL(officialURL string) *Phishing {
	return &Phishing{
		BaseEventType: BaseEventType{
			Name: "phishing",
			Type: "phishing",
		},
		OfficialURL: officialURL,
	}
}

// Bot represents a botnet event type
type Bot struct {
	BaseEventType
	BotType string `json:"bot_type,omitempty"`
}

// NewBot creates a new Bot event type with optional bot type
func NewBot(botType string) *Bot {
	return &Bot{
		BaseEventType: BaseEventType{
			Name: "bot",
			Type: "bot",
		},
		BotType: botType,
	}
}

// Copyright represents a copyright infringement event
type Copyright struct {
	BaseEventType
	CopyrightedWork string `json:"copyrighted_work,omitempty"`
	CopyrightOwner  string `json:"copyright_owner,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	OfficialURL     string `json:"official_url,omitempty"`
}

// NewCopyright creates a new Copyright event type
func NewCopyright(work, owner, protocol string) *Copyright {
	return &Copyright{
		BaseEventType: BaseEventType{
			Name: "copyright",
			Type: "copyright",
		},
		CopyrightedWork: work,
		CopyrightOwner:  owner,
		Protocol:        protocol,
	}
}

// DDoS represents a DDoS attack event
type DDoS struct {
	BaseEventType
}

// NewDDoS creates a new DDoS event type
func NewDDoS() *DDoS {
	return &DDoS{
		BaseEventType: BaseEventType{
			Name: "ddos",
			Type: "ddos",
		},
	}
}

// Fraud represents a fraud event
type Fraud struct {
	BaseEventType
}

// NewFraud creates a new Fraud event type
func NewFraud() *Fraud {
	return &Fraud{
		BaseEventType: BaseEventType{
			Name: "fraud",
			Type: "fraud",
		},
	}
}

// LoginAttack represents a login attack event
type LoginAttack struct {
	BaseEventType
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// NewLoginAttack creates a new LoginAttack event type
func NewLoginAttack(username, password string) *LoginAttack {
	return &LoginAttack{
		BaseEventType: BaseEventType{
			Name: "login_attack",
			Type: "login_attack",
		},
		Username: username,
		Password: password,
	}
}

// MalwareHosting represents malware hosting event
type MalwareHosting struct {
	BaseEventType
	MalwareName string `json:"malware_name,omitempty"`
}

// NewMalwareHosting creates a new MalwareHosting event type
func NewMalwareHosting() *MalwareHosting {
	return &MalwareHosting{
		BaseEventType: BaseEventType{
			Name: "malware_hosting",
			Type: "malware_hosting",
		},
	}
}

// Open represents an open service/port event
type Open struct {
	BaseEventType
	Service string `json:"service,omitempty"`
}

// NewOpen creates a new Open event type
func NewOpen(service string) *Open {
	return &Open{
		BaseEventType: BaseEventType{
			Name: "open",
			Type: "open",
		},
		Service: service,
	}
}

// WebHack represents a web hack event
type WebHack struct {
	BaseEventType
}

// NewWebHack creates a new WebHack event type
func NewWebHack() *WebHack {
	return &WebHack{
		BaseEventType: BaseEventType{
			Name: "web_hack",
			Type: "web_hack",
		},
	}
}

// Blacklist represents a blacklist event
type Blacklist struct {
	BaseEventType
	ListName string `json:"list_name,omitempty"`
}

// NewBlacklist creates a new Blacklist event type
func NewBlacklist(listName string) *Blacklist {
	return &Blacklist{
		BaseEventType: BaseEventType{
			Name: "blacklist",
			Type: "blacklist",
		},
		ListName: listName,
	}
}

// CompromisedMicrosoftExchange represents a compromised Microsoft Exchange server
type CompromisedMicrosoftExchange struct {
	BaseEventType
}

// NewCompromisedMicrosoftExchange creates a new CompromisedMicrosoftExchange event type
func NewCompromisedMicrosoftExchange() *CompromisedMicrosoftExchange {
	return &CompromisedMicrosoftExchange{
		BaseEventType: BaseEventType{
			Name: "compromised_microsoft_exchange",
			Type: "compromised",
		},
	}
}

// CompromisedWebsite represents a compromised website
type CompromisedWebsite struct {
	BaseEventType
	Details string `json:"details,omitempty"`
}

// NewCompromisedWebsite creates a new CompromisedWebsite event type
func NewCompromisedWebsite(details string) *CompromisedWebsite {
	return &CompromisedWebsite{
		BaseEventType: BaseEventType{
			Name: "compromised_website",
			Type: "compromised",
		},
		Details: details,
	}
}

// CompromisedServer represents a compromised server
type CompromisedServer struct {
	BaseEventType
}

// NewCompromisedServer creates a new CompromisedServer event type
func NewCompromisedServer() *CompromisedServer {
	return &CompromisedServer{
		BaseEventType: BaseEventType{
			Name: "compromised_server",
			Type: "compromised",
		},
	}
}

// DDosAmplification represents a DDoS amplification attack
type DDosAmplification struct {
	BaseEventType
	Requests      string `json:"requests,omitempty"`
	Amplification string `json:"amplification,omitempty"`
}

// NewDDosAmplification creates a new DDosAmplification event type
func NewDDosAmplification(requests, amplification string) *DDosAmplification {
	return &DDosAmplification{
		BaseEventType: BaseEventType{
			Name: "ddos_amplification",
			Type: "ddos",
		},
		Requests:      requests,
		Amplification: amplification,
	}
}

// OutdatedDNSSEC represents outdated DNSSEC keys
type OutdatedDNSSEC struct {
	BaseEventType
}

// NewOutdatedDNSSEC creates a new OutdatedDNSSEC event type
func NewOutdatedDNSSEC() *OutdatedDNSSEC {
	return &OutdatedDNSSEC{
		BaseEventType: BaseEventType{
			Name: "outdated_dnssec",
			Type: "open",
		},
	}
}

// SSLPoodle represents SSL Poodle vulnerability
type SSLPoodle struct {
	BaseEventType
}

// NewSSLPoodle creates a new SSLPoodle event type
func NewSSLPoodle() *SSLPoodle {
	return &SSLPoodle{
		BaseEventType: BaseEventType{
			Name: "ssl_poodle",
			Type: "open",
		},
	}
}

// SSLFreak represents SSL Freak vulnerability
type SSLFreak struct {
	BaseEventType
	FreakCipherSuite string `json:"freak_cipher_suite,omitempty"`
}

// NewSSLFreak creates a new SSLFreak event type
func NewSSLFreak(freakCipher string) *SSLFreak {
	return &SSLFreak{
		BaseEventType: BaseEventType{
			Name: "ssl_freak",
			Type: "open",
		},
		FreakCipherSuite: freakCipher,
	}
}

// Malware represents a malware event
type Malware struct {
	BaseEventType
	Infection string `json:"infection,omitempty"`
}

// NewMalware creates a new Malware event type
func NewMalware(infection string) *Malware {
	return &Malware{
		BaseEventType: BaseEventType{
			Name: "malware",
			Type: "malware",
		},
		Infection: infection,
	}
}

// CVE represents a CVE vulnerability
type CVE struct {
	BaseEventType
	CVEName       string `json:"cve_name,omitempty"`
	Score         string `json:"score,omitempty"`
	Severity      string `json:"severity,omitempty"`
	CVSSFramework string `json:"cvss_framework,omitempty"`
}

// NewCVE creates a new CVE event type
func NewCVE(cveName, score, severity string) *CVE {
	return &CVE{
		BaseEventType: BaseEventType{
			Name: "cve",
			Type: "open",
		},
		CVEName:  cveName,
		Score:    score,
		Severity: severity,
	}
}

// IPSpoof represents IP spoofing attack
type IPSpoof struct {
	BaseEventType
	Status      string `json:"status,omitempty"`
	Session     string `json:"session,omitempty"`
	InvolvedNAT bool   `json:"involved_nat,omitempty"`
	Network     string `json:"network,omitempty"`
}

// NewIPSpoof creates a new IPSpoof event type
func NewIPSpoof(status, session string, involvedNAT bool, network string) *IPSpoof {
	return &IPSpoof{
		BaseEventType: BaseEventType{
			Name: "ip_spoof",
			Type: "bot",
		},
		Status:      status,
		Session:     session,
		InvolvedNAT: involvedNAT,
		Network:     network,
	}
}

// PortScan represents a port scanning event
type PortScan struct {
	BaseEventType
}

// NewPortScan creates a new PortScan event type
func NewPortScan() *PortScan {
	return &PortScan{
		BaseEventType: BaseEventType{
			Name: "port_scan",
			Type: "port_scan",
		},
	}
}

// Exploit represents an exploit event
type Exploit struct {
	BaseEventType
}

// NewExploit creates a new Exploit event type
func NewExploit() *Exploit {
	return &Exploit{
		BaseEventType: BaseEventType{
			Name: "exploit",
			Type: "exploit",
		},
	}
}

// Trademark represents a trademark infringement event
type Trademark struct {
	BaseEventType
	Country             string   `json:"country,omitempty"`
	RegistrationNumbers []string `json:"registration_numbers,omitempty"`
	RegistrationOffice  string   `json:"registration_office,omitempty"`
	TrademarkOwner      string   `json:"trademark_owner,omitempty"`
	TrademarkedMaterial string   `json:"trademarked_material,omitempty"`
	OfficialURL         string   `json:"official_url,omitempty"`
}

// NewTrademark creates a new Trademark event type
func NewTrademark(country string, registrationNumbers []string, owner, material string) *Trademark {
	return &Trademark{
		BaseEventType: BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		Country:             country,
		RegistrationNumbers: registrationNumbers,
		TrademarkOwner:      owner,
		TrademarkedMaterial: material,
	}
}

// NewTrademarkWithURL creates a new Trademark event type with official URL
func NewTrademarkWithURL(country string, registrationNumbers []string, owner, material, officialURL string) *Trademark {
	return &Trademark{
		BaseEventType: BaseEventType{
			Name: "trademark",
			Type: "trademark",
		},
		Country:             country,
		RegistrationNumbers: registrationNumbers,
		TrademarkOwner:      owner,
		TrademarkedMaterial: material,
		OfficialURL:         officialURL,
	}
}

// IllegalAdvertisement represents an illegal advertisement event
type IllegalAdvertisement struct {
	BaseEventType
}

// NewIllegalAdvertisement creates a new IllegalAdvertisement event type
func NewIllegalAdvertisement() *IllegalAdvertisement {
	return &IllegalAdvertisement{
		BaseEventType: BaseEventType{
			Name: "illegal_advertisement",
			Type: "illegal_advertisement",
		},
	}
}

// MaliciousActivity represents a malicious activity event
type MaliciousActivity struct {
	BaseEventType
}

// NewMaliciousActivity creates a new MaliciousActivity event type
func NewMaliciousActivity() *MaliciousActivity {
	return &MaliciousActivity{
		BaseEventType: BaseEventType{
			Name: "malicious_activity",
			Type: "malicious_activity",
		},
	}
}

// Spamvertised represents spamvertised website event
type Spamvertised struct {
	BaseEventType
}

// NewSpamvertised creates a new Spamvertised event type
func NewSpamvertised() *Spamvertised {
	return &Spamvertised{
		BaseEventType: BaseEventType{
			Name: "spamvertised",
			Type: "spamvertised",
		},
	}
}

// DNSBlocklist represents a DNS blocklist event
type DNSBlocklist struct {
	BaseEventType
}

// NewDNSBlocklist creates a new DNSBlocklist event type
func NewDNSBlocklist() *DNSBlocklist {
	return &DNSBlocklist{
		BaseEventType: BaseEventType{
			Name: "dns_blocklist",
			Type: "dns_blocklist",
		},
	}
}

// CompromisedAccount represents a compromised account event
type CompromisedAccount struct {
	BaseEventType
	Account string `json:"account,omitempty"`
}

// NewCompromisedAccount creates a new CompromisedAccount event type
func NewCompromisedAccount(account string) *CompromisedAccount {
	return &CompromisedAccount{
		BaseEventType: BaseEventType{
			Name: "compromised_account",
			Type: "compromised",
		},
		Account: account,
	}
}

// ChildAbuse represents a child abuse event
type ChildAbuse struct {
	BaseEventType
}

// NewChildAbuse creates a new ChildAbuse event type
func NewChildAbuse() *ChildAbuse {
	return &ChildAbuse{
		BaseEventType: BaseEventType{
			Name: "child_abuse",
			Type: "child_abuse",
		},
	}
}

// Doxing represents a doxing/privacy violation event
type Doxing struct {
	BaseEventType
}

// NewDoxing creates a new Doxing event type
func NewDoxing() *Doxing {
	return &Doxing{
		BaseEventType: BaseEventType{
			Name: "doxing",
			Type: "doxing",
		},
	}
}

// WebCrawler represents a web crawler/bot event
type WebCrawler struct {
	BaseEventType
}

// NewWebCrawler creates a new WebCrawler event type
func NewWebCrawler() *WebCrawler {
	return &WebCrawler{
		BaseEventType: BaseEventType{
			Name: "web_crawler",
			Type: "web_crawler",
		},
	}
}

// RogueDNS represents a rogue DNS server event
type RogueDNS struct {
	BaseEventType
}

// NewRogueDNS creates a new RogueDNS event type
func NewRogueDNS() *RogueDNS {
	return &RogueDNS{
		BaseEventType: BaseEventType{
			Name: "rogue_dns",
			Type: "rogue_dns",
		},
	}
}

// Defacement represents a website defacement event
type Defacement struct {
	BaseEventType
}

// NewDefacement creates a new Defacement event type
func NewDefacement() *Defacement {
	return &Defacement{
		BaseEventType: BaseEventType{
			Name: "defacement",
			Type: "defacement",
		},
	}
}

// Unknown represents an unknown event type
type Unknown struct {
	BaseEventType
}

// NewUnknown creates a new Unknown event type
func NewUnknown() *Unknown {
	return &Unknown{
		BaseEventType: BaseEventType{
			Name: "unknown",
			Type: "unknown",
		},
	}
}

// Violence represents a violence event
type Violence struct {
	BaseEventType
}

// NewViolence creates a new Violence event type
func NewViolence() *Violence {
	return &Violence{
		BaseEventType: BaseEventType{
			Name: "violence",
			Type: "violence",
		},
	}
}

// Propaganda represents a propaganda event
type Propaganda struct {
	BaseEventType
}

// NewPropaganda creates a new Propaganda event type
func NewPropaganda() *Propaganda {
	return &Propaganda{
		BaseEventType: BaseEventType{
			Name: "propaganda",
			Type: "propaganda",
		},
	}
}

// AuthFailure represents an authentication failure event (DMARC)
type AuthFailure struct {
	BaseEventType
}

// NewAuthFailure creates a new AuthFailure event type
func NewAuthFailure() *AuthFailure {
	return &AuthFailure{
		BaseEventType: BaseEventType{
			Name: "auth_failure",
			Type: "auth_failure",
		},
	}
}

// Backdoor represents a backdoor/web shell event
type Backdoor struct {
	BaseEventType
}

// NewBackdoor creates a new Backdoor event type
func NewBackdoor() *Backdoor {
	return &Backdoor{
		BaseEventType: BaseEventType{
			Name: "backdoor",
			Type: "backdoor",
		},
	}
}

// Censorship represents a censorship event
type Censorship struct {
	BaseEventType
}

// NewCensorship creates a new Censorship event type
func NewCensorship() *Censorship {
	return &Censorship{
		BaseEventType: BaseEventType{
			Name: "censorship",
			Type: "censorship",
		},
	}
}
