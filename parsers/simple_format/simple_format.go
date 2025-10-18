package simple_format

import (
	"strings"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/common"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// eventTypeFactory is a function that creates an event type
type eventTypeFactory func() events.EventType

// typeMapping represents different ways to map to event types
type typeMapping struct {
	// Direct event type factory
	directType eventTypeFactory
	// Header-based mapping
	headers map[string]map[string]eventTypeFactory
	// Body-based mapping
	body map[string]eventTypeFactory
	// Default type when no specific match
	defaultType eventTypeFactory
}

// simpleDataMappings maps email addresses/domains to event types
var simpleDataMappings = map[string]*typeMapping{
	"no-auto-replies@hopone.net": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	".mandarinmedien.de": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"abuse@haveland.com": {
		directType: func() events.EventType { return events.NewDNSBlocklist() },
	},
	"admin@inter-systeme.ca": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@iinet.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"csirt-no-reply@ics.muni.cz": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"scanning":     func() events.EventType { return events.NewPortScan() },
				"brute force":  func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@nsm.pl": {
		directType: func() events.EventType { return events.NewSpam() }, // MailRelayAttempt -> Spam
	},
	"sauce-daemon@chiark.greenend.org.uk": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"mtso@matera.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"hacking activity": func() events.EventType { return events.NewPortScan() },
			},
		},
	},
	"hostmaster@wired-net.de": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ssh: banned": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@skymesh.net.au": {
		directType: func() events.EventType { return events.NewWebCrawler() },
	},
	"abuse@open-minds.org": {
		directType: func() events.EventType { return events.NewDNSBlocklist() },
	},
	"abuse@clusters.de": {
		body: map[string]eventTypeFactory{
			"postfix": func() events.EventType { return events.NewLoginAttack("", "") },
		},
		defaultType: func() events.EventType { return events.NewExploit() },
	},
	"abuse@valuehost.ru": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"bruteforce": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"devnull@openbl.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"bruteforce": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@vikingserv.net": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"postmaster@reachone.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"abuse@pnwx.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"saas.noc@cp.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"noreply@aldridge.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"brute force": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"mailling@malekal.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"modsec": func() events.EventType { return events.NewWebHack() },
			},
		},
	},
	"admin@virtualmarctek.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"ids1@space.net": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"botlook@googlemail.com": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"@edresults.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ssh": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"root@kim.kairosnet.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"knock@iu.edu": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@thirdeye.it": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@extro-media.de": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"admin@comerisparmio.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"nobody@woody.ch": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"abuse@registro.br": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"scan": func() events.EventType { return events.NewPortScan() },
			},
		},
	},
	"cert@woorifis.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"unauthorised": func() events.EventType { return events.NewPortScan() },
			},
		},
	},
	"info@level3.es": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"brute force": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	".uk2net.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"admin@ictabc.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"fail2ban@gloomytrousers.co.uk": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abusereports@gameservers.com": {
		directType: func() events.EventType { return events.NewBot("") },
	},
	"monitoring@smartservercontrol.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"abuse@ru-hoster.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ddos": func() events.EventType { return events.NewBot("") },
			},
		},
	},
	"support@cnservers.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ddos": func() events.EventType { return events.NewBot("") },
			},
		},
	},
	"@convergeict.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ddos": func() events.EventType { return events.NewPortScan() },
			},
		},
	},
	"@easysol.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"trojan":  func() events.EventType { return events.NewMalware("") },
				"malware": func() events.EventType { return events.NewMalware("") },
			},
		},
	},
	"ddos-response@nfoservers.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"resolver":                   func() events.EventType { return events.NewOpen("dns") },
				"ntp":                        func() events.EventType { return events.NewOpen("ntp") },
				"exploitable chargen service": func() events.EventType { return events.NewExploit() },
				"Compromised host used":      func() events.EventType { return events.NewBot("") },
				"open snmp service":          func() events.EventType { return events.NewOpen("snmp") },
				"ssdp":                       func() events.EventType { return events.NewOpen("ssdp") },
			},
		},
	},
	"saas.noc@owmessaging.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@ix.de": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"[auto-generated] spam": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"@profihost.ag": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"brute-force": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@agarik.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"bruteforce": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@hobby.nl": {
		directType: func() events.EventType { return events.NewBot("") },
	},
	"ddos-response@a-e.es": {
		directType: func() events.EventType { return events.NewBot("") },
	},
	"donotanswer@4friends.eu": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@prolink.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@accentikainternet.co.uk": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@codeaholics.org": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"csirt@muni.cz": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"brute force": func() events.EventType { return events.NewLoginAttack("", "") },
				"scanning":    func() events.EventType { return events.NewPortScan() },
				"honeypot":    func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"kpgraham@gmail.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@xictron.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@psych.columbia.edu": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@foodavenue.fr": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"takedowns@lifelock.com": {
		directType: func() events.EventType { return events.NewCopyright("", "", "") },
	},
	"security@defcon.gofferje.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse+comcast.net@physics.mcgill.ca": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"security@usu.edu": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"fail2ban@midras.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"fail2ban@kamadu.eu": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"root@janeric.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"please_do_not_reply@realconnect.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@axmo12.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@scrc.umanitoba.ca": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"root@host-82-145-38-119.rsclientdns.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"abuse@unleashed-technologies.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@aviacode.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"windy_1@skyhighway.com": {
		directType: func() events.EventType { return events.NewBot("") },
	},
	"hostmaster@processnet.hu": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"allan@al-ter.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@wesleyan.edu": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@maastrek.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"pentti.sarajarvi@nbl.fi": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"hostmaster@htsis.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"jr@rh-tec.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@sae.ru": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@shanock.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@telecom-mk.ru": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"wgkmbox-abrpt23@yahoo.com": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"@zweije.nl": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"worm": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"@tnbankers.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"vpn": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"cais@cais.rnp.br": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"masataka_o@yahoo.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@software.coop": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@antinode.info": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@ucom.ne.jp": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"admin@meriserver.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"jpodaniel@hotmail.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"jonathandl2@verizon.net": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"abuse@exitcertified.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"ivan@kwiatkowski.fr": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"postmaster@colemansprinting.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"ccordova@optical.com.pe": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"julie@ixo.ca": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"@mindspring.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"scam": func() events.EventType { return events.NewSpam() },
				"http": func() events.EventType { return events.NewWebHack() },
			},
		},
	},
	"@beyondthepale.ie": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"root@gci.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"cert.opl@orange.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"login": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"security.feedback@level3.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"copyright":   func() events.EventType { return events.NewCopyright("", "", "") },
				"infringement": func() events.EventType { return events.NewCopyright("", "", "") },
			},
		},
	},
	"jean.lemaire@decimal.ca": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"julien.ahrens@fks.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"rstout@lastescape.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"admin@major2nd.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"peter@farmsideltd.co.nz": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"rgronlie@shaw.ca": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"security.surveillance@wipro.com": {
		directType: func() events.EventType { return events.NewWebCrawler() },
	},
	"root@jedla.be": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"security@www.sondrakistan.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@www.sondrakistan.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@univsw00.universal-sw.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@mx0.uce-less.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@shell.connactivity.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@web1.connactivity.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"vlada@infosky.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"tspragens@systat.de": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"dwatts@dimentech.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"noc@011ltd.net": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"no-reply@snel.com": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"nick.adie@brokenmould.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@g1ga.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"info@enlytend.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"routerset@hotmail.co.uk": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"govcert@gov.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"admin@rosborg-as.dk": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"scott@waveconcepts.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"hawkeye1111@spamcop.net": {
		directType: func() events.EventType { return events.NewOpen("proxy") },
	},
	"finches@portadmiral.org": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"artasov@exima.ru": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@carlc.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"info@koenig-lars.de": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"tech@earthville.org": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"mats.olsson@enburk.se": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@dls-consulting.net": {
		directType: func() events.EventType { return events.NewPhishing() },
	},
	"abuse@scasey.com": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"jhayman@racc2000.com": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"sander@trefnet.nl": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@free-ts.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"psne@flipkart.com": {
		directType: func() events.EventType { return events.NewWebCrawler() },
	},
	"abuse-report@vaniersel.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@verifysystems.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"matt@disneyonline.ca": {
		directType: func() events.EventType { return events.NewWebHack() },
	},
	"rlbard@universal4hosting.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"attack-report@courbis.fr": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"mitxelena@jlazkano.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@mail.padinet.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@oktennis.thirdeye.it": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"lapurdi@jlazkano.net": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@anasta.eu": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@cockatoo.mainboarder.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@mail.anasta.eu": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@cassiopeia.wm4d.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"no-reply@indas.ro": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"orion@getseenmedia.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@prioris.net": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"fabcar99@gmail.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"noc@ihost.md": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@bmk-it.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"info@frontnetzwerk.de": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"rfusci@gmail.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"abuse@mweb.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"@griffithscorp.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"virus": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"hostmaster@catwhisker.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ssh": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"bpb@umich.edu": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"scam": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"root@rcw.me.uk": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"network abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"@rcn.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"flooding": func() events.EventType { return events.NewWebHack() },
			},
		},
	},
	"caudilldk@gmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"fail2ban": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"@thinlink.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"dos attack": func() events.EventType { return events.NewDDoS() },
			},
		},
	},
	"abuse@freshdot.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"bruteforce": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"briandav7@gmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"network intrusion": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"network.integrity@hotshockband.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"hack attack": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"chris@diver.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"attack on": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"admin@alteredstates.info": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"attack from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"yehuda@ymkatz.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"lau-josefsen@hotmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"3535safe@gmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"root@ks24828.kimsufi.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"sebastian@nohn.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"netops@coloblox.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"login attempts": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"dhcain@verizon.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"spam": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"abuse@cableone.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse complaint": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"admin@dttechnologies.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"admin@picknic.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse log": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"abuse@veg.animx.eu.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"attempted breakin": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@animx.eu.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"attempted mail relay": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"abuse@modernhost.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"complaint regarding": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"szekeres@dmedia.hu": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"fail2ban": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"admin@bluepepper.me": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"fail2ban": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"support@copiergeeks.biz": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"failed login attempts": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@nk99.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"http scan from": func() events.EventType { return events.NewWebCrawler() },
			},
		},
	},
	"112211.631@compuserve.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ip address": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"abuse@servnet.dk": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@redfish-solutions.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"spam from": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"abuse@cordax.publicvm.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"unauthorized": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@dmedia.hu": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"fail2ban": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"hostmaster@intennes.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"alert@jlanhosting.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"elgrande71@free.fr": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"fail2ban": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"postmaster@gea.uni-sofia.bg": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"marcosoussana@gmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"wordpress@weatheralertcentral.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"ddos": func() events.EventType { return events.NewDDoS() },
			},
		},
	},
	"serverinvestigation@gmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"failed login": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"telejt@shaw.ca": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"your client": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"jason.gilbert@xtra.co.nz": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"website": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@perl.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"spam": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"gpiekarczyk@senetic.com": {
		headers: map[string]map[string]eventTypeFactory{
			"thread-topic": {
				"login": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"lenartg@invitel.co.hu": {
		headers: map[string]map[string]eventTypeFactory{
			"thread-topic": {
				"smtp auth": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"takasuite@hotmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"report scam": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"george@rewci.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"attack": func() events.EventType { return events.NewWebHack() },
			},
		},
	},
	"abuse@light-gap.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abusive actions": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"postmaster@okla.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"spam": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"ni.security.operations.center@aexp.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"malicious activity": func() events.EventType { return events.NewWebHack() },
			},
		},
	},
	"123corey@gmail.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"blocked": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse-handler@math.ubc.ca": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"security incident": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"ab@ixo.ca": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"spam from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"brian@brianmartin.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"compromised server": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse-report@project76.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"hacking attempts": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"geoffdown@fastmail.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"hacking attempt": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"root@mexxem.ro": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"fail2ban": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"support@agentur2c.de": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"root@parallelrpi.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"root@plesk1.wsartori.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"abuse@christianhofer.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"root@netxms.org": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@web4ce.cz": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"incident-report@bitninja.io": {
		directType: func() events.EventType { return events.NewWebCrawler() },
	},
	"noreply@abansysandhostytec.com": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"web service": func() events.EventType { return events.NewWebHack() },
				"ftp service": func() events.EventType { return events.NewLoginAttack("", "") },
				"ssh service": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"report@redsnitch.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"Abuse report for": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@telbiur.com.pl": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"Abuse from": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@bmx.lucky.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"Automatic abuse report": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@amx.lucky.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"Automatic abuse report": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"fail2ban@cmx.lucky.net": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"Automatic abuse report": func() events.EventType { return events.NewLoginAttack("", "") },
			},
		},
	},
	"steven@rivercity.net.au": {
		headers: map[string]map[string]eventTypeFactory{
			"subject": {
				"Abuse report:": func() events.EventType { return events.NewSpam() },
			},
		},
	},
	"@physics.mcgill.ca": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"security@unicamp.br": {
		directType: func() events.EventType { return events.NewPortScan() },
	},
	"abuse@itl.pl": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"bob@bobcatos.com": {
		directType: func() events.EventType { return events.NewLoginAttack("", "") },
	},
	"root@bk1.eure.it": {
		directType: func() events.EventType { return events.NewSpam() },
	},
	"constant.co.uk": {
		directType: func() events.EventType { return events.NewSpam() },
	},
}

// abuseFromApps are strings that indicate login attacks when found in body
var abuseFromApps = []string{
	"sshd[",
	"proftpd[",
	"FTP session opened",
	"wp-login.php",
	"authentication failed",
	"Wordpress Login",
}

func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
	body, _ := common.GetBody(serializedEmail, false)
	subject, _ := common.GetSubject(serializedEmail, false)
	fromAddr, _ := common.GetFrom(serializedEmail, false)

	// Check if subject starts with "Abuse from"
	if subject != "" && strings.HasPrefix(subject, "Abuse from") {
		// Check for login attack indicators in body
		for _, app := range abuseFromApps {
			if strings.Contains(body, app) {
				return p.createSimpleEvent(serializedEmail, events.NewLoginAttack("", ""))
			}
		}
	}

	// Check for "abuse report for" in subject
	if subject != "" && strings.Contains(strings.ToLower(subject), "abuse report for") {
		// Check for login attack indicators in body
		for _, app := range abuseFromApps {
			if strings.Contains(body, app) {
				return p.createSimpleEvent(serializedEmail, events.NewLoginAttack("", ""))
			}
		}
	}

	// Match from address against mappings
	if fromAddr != "" {
		fromAddrLower := strings.ToLower(fromAddr)

		for pattern, mapping := range simpleDataMappings {
			// Check if pattern matches (either exact match or substring match for patterns starting with @)
			if pattern == fromAddrLower || strings.Contains(fromAddrLower, pattern) {
				eventType := p.resolveEventType(mapping, serializedEmail, body)
				if eventType != nil {
					return p.createSimpleEvent(serializedEmail, eventType)
				}
			}
		}
	}

	return nil, nil
}

func (p *Parser) resolveEventType(mapping *typeMapping, serializedEmail *email.SerializedEmail, body string) events.EventType {
	// Check for direct type
	if mapping.directType != nil {
		return mapping.directType()
	}

	// Start with default type if present
	var finalType events.EventType
	if mapping.defaultType != nil {
		finalType = mapping.defaultType()
	}

	// Check headers
	if mapping.headers != nil && serializedEmail.Headers != nil {
		for headerName, keywordMap := range mapping.headers {
			if headerValues, ok := serializedEmail.Headers[headerName]; ok && len(headerValues) > 0 {
				headerValue := strings.ToLower(headerValues[0])
				for keyword, factory := range keywordMap {
					if strings.Contains(headerValue, strings.ToLower(keyword)) {
						finalType = factory()
						break
					}
				}
			}
		}
	}

	// Check body
	if mapping.body != nil {
		bodyLower := strings.ToLower(body)
		for keyword, factory := range mapping.body {
			if strings.Contains(bodyLower, strings.ToLower(keyword)) {
				finalType = factory()
				break
			}
		}
	}

	return finalType
}

func (p *Parser) createSimpleEvent(serializedEmail *email.SerializedEmail, eventType events.EventType) ([]*events.Event, error) {
	event := events.NewEvent("simple_format")

	// Set IP from subject
	if serializedEmail.Headers != nil {
		if subject, ok := serializedEmail.Headers["subject"]; ok && len(subject) > 0 {
			event.IP = subject[0]
		}

		// Set event date from date header
		if dateHeaders, ok := serializedEmail.Headers["date"]; ok && len(dateHeaders) > 0 {
			if eventDate := email.ParseDate(dateHeaders[0]); eventDate != nil {
				event.EventDate = eventDate
			}
		}
	}

	event.EventTypes = []events.EventType{eventType}

	return []*events.Event{event}, nil
}

// GetPriority returns the parser priority (lower numbers run first)
func (p *Parser) GetPriority() int {
	return 2000
}
