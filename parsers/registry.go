package parsers

import (
	"sort"

	"github.com/abusix/inbound-parsers/events"
	"github.com/abusix/inbound-parsers/parsers/base"
	"github.com/abusix/inbound-parsers/pkg/email"
	"github.com/abusix/inbound-parsers/parsers/abuse_oneprovider"
	"github.com/abusix/inbound-parsers/parsers/abusehub_nl"
	"github.com/abusix/inbound-parsers/parsers/abusetrue_nl"
	"github.com/abusix/inbound-parsers/parsers/abusix"
	"github.com/abusix/inbound-parsers/parsers/acastano"
	"github.com/abusix/inbound-parsers/parsers/accenture"
	"github.com/abusix/inbound-parsers/parsers/acedatacenter"
	"github.com/abusix/inbound-parsers/parsers/acns"
	"github.com/abusix/inbound-parsers/parsers/adciberespaco"
	"github.com/abusix/inbound-parsers/parsers/agouros"
	"github.com/abusix/inbound-parsers/parsers/aiplex"
	"github.com/abusix/inbound-parsers/parsers/akamai"
	"github.com/abusix/inbound-parsers/parsers/amasha"
	"github.com/abusix/inbound-parsers/parsers/amazon"
	"github.com/abusix/inbound-parsers/parsers/antipiracy_report"
	"github.com/abusix/inbound-parsers/parsers/antipiracy"
	"github.com/abusix/inbound-parsers/parsers/antipiracyprotection"
	"github.com/abusix/inbound-parsers/parsers/anvisa_gov"
	"github.com/abusix/inbound-parsers/parsers/aol"
	"github.com/abusix/inbound-parsers/parsers/ap_markmonitor"
	"github.com/abusix/inbound-parsers/parsers/aparlay"
	"github.com/abusix/inbound-parsers/parsers/apiccopyright"
	"github.com/abusix/inbound-parsers/parsers/arkadruk"
	"github.com/abusix/inbound-parsers/parsers/artplanet"
	"github.com/abusix/inbound-parsers/parsers/aruba"
	"github.com/abusix/inbound-parsers/parsers/att"
	"github.com/abusix/inbound-parsers/parsers/attributor"
	"github.com/abusix/inbound-parsers/parsers/autofusion"
	"github.com/abusix/inbound-parsers/parsers/avoxi"
	"github.com/abusix/inbound-parsers/parsers/axghouse"
	"github.com/abusix/inbound-parsers/parsers/axur"
	"github.com/abusix/inbound-parsers/parsers/b_monitor"
	"github.com/abusix/inbound-parsers/parsers/barrettlawgroup"
	"github.com/abusix/inbound-parsers/parsers/baysidecorp"
	"github.com/abusix/inbound-parsers/parsers/bb"
	"github.com/abusix/inbound-parsers/parsers/bbc"
	"github.com/abusix/inbound-parsers/parsers/bellsouth"
	"github.com/abusix/inbound-parsers/parsers/beygoo"
	"github.com/abusix/inbound-parsers/parsers/bibo"
	"github.com/abusix/inbound-parsers/parsers/bitninja"
	"github.com/abusix/inbound-parsers/parsers/bka"
	"github.com/abusix/inbound-parsers/parsers/black_dura"
	"github.com/abusix/inbound-parsers/parsers/bluevoyant"
	"github.com/abusix/inbound-parsers/parsers/bnshosting"
	"github.com/abusix/inbound-parsers/parsers/bofa"
	"github.com/abusix/inbound-parsers/parsers/botnet_tracker"
	"github.com/abusix/inbound-parsers/parsers/bp_corsearch"
	"github.com/abusix/inbound-parsers/parsers/bradesco"
	"github.com/abusix/inbound-parsers/parsers/brandmonitor"
	"github.com/abusix/inbound-parsers/parsers/brandprotection"
	"github.com/abusix/inbound-parsers/parsers/brandsecurity_ru"
	"github.com/abusix/inbound-parsers/parsers/brandshield"
	"github.com/abusix/inbound-parsers/parsers/bsi"
	"github.com/abusix/inbound-parsers/parsers/bt"
	"github.com/abusix/inbound-parsers/parsers/buerki"
	"github.com/abusix/inbound-parsers/parsers/buycheaprdp"
	"github.com/abusix/inbound-parsers/parsers/bwbmodels"
	"github.com/abusix/inbound-parsers/parsers/bytescare"
	"github.com/abusix/inbound-parsers/parsers/cammodelprotect"
	"github.com/abusix/inbound-parsers/parsers/cavac"
	"github.com/abusix/inbound-parsers/parsers/ccirc"
	"github.com/abusix/inbound-parsers/parsers/cdar_westpac"
	"github.com/abusix/inbound-parsers/parsers/centurylink"
	"github.com/abusix/inbound-parsers/parsers/centurylinkservices"
	"github.com/abusix/inbound-parsers/parsers/cert_bz"
	"github.com/abusix/inbound-parsers/parsers/cert_ee"
	"github.com/abusix/inbound-parsers/parsers/cert_es"
	"github.com/abusix/inbound-parsers/parsers/cert_gib"
	"github.com/abusix/inbound-parsers/parsers/cert_gov"
	"github.com/abusix/inbound-parsers/parsers/cert_hr"
	"github.com/abusix/inbound-parsers/parsers/cert_in"
	"github.com/abusix/inbound-parsers/parsers/cert_lt"
	"github.com/abusix/inbound-parsers/parsers/cert_no"
	"github.com/abusix/inbound-parsers/parsers/cert_nz"
	"github.com/abusix/inbound-parsers/parsers/cert_pl"
	"github.com/abusix/inbound-parsers/parsers/cert_pt"
	"github.com/abusix/inbound-parsers/parsers/cert_rcts"
	"github.com/abusix/inbound-parsers/parsers/cert_ro"
	"github.com/abusix/inbound-parsers/parsers/cert_ua"
	"github.com/abusix/inbound-parsers/parsers/certat"
	"github.com/abusix/inbound-parsers/parsers/certbr"
	"github.com/abusix/inbound-parsers/parsers/chaturbate"
	"github.com/abusix/inbound-parsers/parsers/checkphish"
	"github.com/abusix/inbound-parsers/parsers/circllu"
	"github.com/abusix/inbound-parsers/parsers/ciu_online"
	"github.com/abusix/inbound-parsers/parsers/cloudflare"
	"github.com/abusix/inbound-parsers/parsers/cloudns"
	"github.com/abusix/inbound-parsers/parsers/cnsd_gob_pe"
	"github.com/abusix/inbound-parsers/parsers/cogent"
	"github.com/abusix/inbound-parsers/parsers/colocationamerica"
	"github.com/abusix/inbound-parsers/parsers/columbiaedu"
	"github.com/abusix/inbound-parsers/parsers/comcast"
	"github.com/abusix/inbound-parsers/parsers/comeso"
	"github.com/abusix/inbound-parsers/parsers/communicationvalley"
	"github.com/abusix/inbound-parsers/parsers/comvive"
	"github.com/abusix/inbound-parsers/parsers/copyright_compliance"
	"github.com/abusix/inbound-parsers/parsers/copyright_integrity"
	"github.com/abusix/inbound-parsers/parsers/counterfeittechnology"
	"github.com/abusix/inbound-parsers/parsers/courbis"
	"github.com/abusix/inbound-parsers/parsers/courts_in"
	"github.com/abusix/inbound-parsers/parsers/cpanel"
	"github.com/abusix/inbound-parsers/parsers/cpragency"
	"github.com/abusix/inbound-parsers/parsers/crdflabs"
	"github.com/abusix/inbound-parsers/parsers/crm_wix"
	"github.com/abusix/inbound-parsers/parsers/crowdstrike"
	"github.com/abusix/inbound-parsers/parsers/csa"
	"github.com/abusix/inbound-parsers/parsers/cscglobal"
	"github.com/abusix/inbound-parsers/parsers/csirt_br"
	"github.com/abusix/inbound-parsers/parsers/csirt_cz"
	"github.com/abusix/inbound-parsers/parsers/csirt_divd"
	"github.com/abusix/inbound-parsers/parsers/csirt_dnofd"
	"github.com/abusix/inbound-parsers/parsers/csirt_muni"
	"github.com/abusix/inbound-parsers/parsers/csis"
	"github.com/abusix/inbound-parsers/parsers/customvisuals"
	"github.com/abusix/inbound-parsers/parsers/cyber_gc"
	"github.com/abusix/inbound-parsers/parsers/cyber999"
	"github.com/abusix/inbound-parsers/parsers/cyberint"
	"github.com/abusix/inbound-parsers/parsers/cybertip"
	"github.com/abusix/inbound-parsers/parsers/cyberweb"
	"github.com/abusix/inbound-parsers/parsers/cyble"
	"github.com/abusix/inbound-parsers/parsers/d3lab"
	"github.com/abusix/inbound-parsers/parsers/darklist"
	"github.com/abusix/inbound-parsers/parsers/datapacket"
	"github.com/abusix/inbound-parsers/parsers/dcpmail"
	"github.com/abusix/inbound-parsers/parsers/dd_tech"
	"github.com/abusix/inbound-parsers/parsers/ddos_google"
	"github.com/abusix/inbound-parsers/parsers/debian"
	"github.com/abusix/inbound-parsers/parsers/defaria"
	"github.com/abusix/inbound-parsers/parsers/deft"
	"github.com/abusix/inbound-parsers/parsers/deloite"
	"github.com/abusix/inbound-parsers/parsers/desmoweb"
	"github.com/abusix/inbound-parsers/parsers/dgn"
	"github.com/abusix/inbound-parsers/parsers/dgt"
	"github.com/abusix/inbound-parsers/parsers/digiguardians"
	"github.com/abusix/inbound-parsers/parsers/digiturk"
	"github.com/abusix/inbound-parsers/parsers/disney"
	"github.com/abusix/inbound-parsers/parsers/djr_co"
	"github.com/abusix/inbound-parsers/parsers/dmarc_xml"
	"github.com/abusix/inbound-parsers/parsers/dmca_com"
	"github.com/abusix/inbound-parsers/parsers/dmca_pro"
	"github.com/abusix/inbound-parsers/parsers/dmcaforce"
	"github.com/abusix/inbound-parsers/parsers/dmcapiracyprevention"
	"github.com/abusix/inbound-parsers/parsers/dnainternet"
	"github.com/abusix/inbound-parsers/parsers/dnsc"
	"github.com/abusix/inbound-parsers/parsers/docusign"
	"github.com/abusix/inbound-parsers/parsers/domainabusereporting"
	"github.com/abusix/inbound-parsers/parsers/domainoo"
	"github.com/abusix/inbound-parsers/parsers/doppel"
	"github.com/abusix/inbound-parsers/parsers/dreamworldpartners"
	"github.com/abusix/inbound-parsers/parsers/dreyfus"
	"github.com/abusix/inbound-parsers/parsers/easysol"
	"github.com/abusix/inbound-parsers/parsers/ebay"
	"github.com/abusix/inbound-parsers/parsers/ebrand"
	"github.com/abusix/inbound-parsers/parsers/ebs"
	"github.com/abusix/inbound-parsers/parsers/eca"
	"github.com/abusix/inbound-parsers/parsers/ecucert"
	"github.com/abusix/inbound-parsers/parsers/eisys"
	"github.com/abusix/inbound-parsers/parsers/ellematthewsmodel"
	"github.com/abusix/inbound-parsers/parsers/enf_meta"
	"github.com/abusix/inbound-parsers/parsers/enfappdetex"
	"github.com/abusix/inbound-parsers/parsers/entura"
	"github.com/abusix/inbound-parsers/parsers/ephemeron"
	"github.com/abusix/inbound-parsers/parsers/eq_ee"
	"github.com/abusix/inbound-parsers/parsers/esp"
	"github.com/abusix/inbound-parsers/parsers/espresso"
	"github.com/abusix/inbound-parsers/parsers/etoolkit"
	"github.com/abusix/inbound-parsers/parsers/etotalhost"
	"github.com/abusix/inbound-parsers/parsers/europa_eu"
	"github.com/abusix/inbound-parsers/parsers/exemail"
	"github.com/abusix/inbound-parsers/parsers/experian"
	"github.com/abusix/inbound-parsers/parsers/expressvpn"
	"github.com/abusix/inbound-parsers/parsers/eyeonpiracy"
	"github.com/abusix/inbound-parsers/parsers/facct"
	"github.com/abusix/inbound-parsers/parsers/fail2ban"
	"github.com/abusix/inbound-parsers/parsers/fbi_ipv6home"
	"github.com/abusix/inbound-parsers/parsers/fbs"
	"github.com/abusix/inbound-parsers/parsers/feedback_loop"
	"github.com/abusix/inbound-parsers/parsers/fhs"
	"github.com/abusix/inbound-parsers/parsers/flyhosting"
	"github.com/abusix/inbound-parsers/parsers/fmtsoperation"
	"github.com/abusix/inbound-parsers/parsers/fondia"
	"github.com/abusix/inbound-parsers/parsers/fraudwatch"
	"github.com/abusix/inbound-parsers/parsers/fraudwatchinternational"
	"github.com/abusix/inbound-parsers/parsers/freedomtech"
	"github.com/abusix/inbound-parsers/parsers/friendmts"
	"github.com/abusix/inbound-parsers/parsers/fsec"
	"github.com/abusix/inbound-parsers/parsers/fsm"
	"github.com/abusix/inbound-parsers/parsers/gastecnologia"
	"github.com/abusix/inbound-parsers/parsers/generic_spam_trap"
	"github.com/abusix/inbound-parsers/parsers/ginernet"
	"github.com/abusix/inbound-parsers/parsers/giorgioarmaniweb"
	"github.com/abusix/inbound-parsers/parsers/gmail_parser"
	"github.com/abusix/inbound-parsers/parsers/gmx_com"
	"github.com/abusix/inbound-parsers/parsers/gmx"
	"github.com/abusix/inbound-parsers/parsers/gold_parser"
	"github.com/abusix/inbound-parsers/parsers/googlesafebrowsing"
	"github.com/abusix/inbound-parsers/parsers/govcert_ch"
	"github.com/abusix/inbound-parsers/parsers/griffeshield"
	"github.com/abusix/inbound-parsers/parsers/group_ib"
	"github.com/abusix/inbound-parsers/parsers/hack_hunt"
	"github.com/abusix/inbound-parsers/parsers/heficed"
	"github.com/abusix/inbound-parsers/parsers/herrbischoff"
	"github.com/abusix/inbound-parsers/parsers/hetzner"
	"github.com/abusix/inbound-parsers/parsers/hfmarket"
	"github.com/abusix/inbound-parsers/parsers/hispasec"
	"github.com/abusix/inbound-parsers/parsers/hkcert"
	"github.com/abusix/inbound-parsers/parsers/home"
	"github.com/abusix/inbound-parsers/parsers/honeypots_tk"
	"github.com/abusix/inbound-parsers/parsers/hostdime"
	"github.com/abusix/inbound-parsers/parsers/hosteurope"
	"github.com/abusix/inbound-parsers/parsers/hostfission"
	"github.com/abusix/inbound-parsers/parsers/hostopia"
	"github.com/abusix/inbound-parsers/parsers/hostroyale"
	"github.com/abusix/inbound-parsers/parsers/hotmail"
	"github.com/abusix/inbound-parsers/parsers/humongoushibiscus"
	"github.com/abusix/inbound-parsers/parsers/hyperfilter"
	"github.com/abusix/inbound-parsers/parsers/ibcom"
	"github.com/abusix/inbound-parsers/parsers/ibm"
	"github.com/abusix/inbound-parsers/parsers/icscards"
	"github.com/abusix/inbound-parsers/parsers/ifpi"
	"github.com/abusix/inbound-parsers/parsers/iheatwithoil"
	"github.com/abusix/inbound-parsers/parsers/ilvasapolli"
	"github.com/abusix/inbound-parsers/parsers/inaxas"
	"github.com/abusix/inbound-parsers/parsers/incopro"
	"github.com/abusix/inbound-parsers/parsers/infringements_cc"
	"github.com/abusix/inbound-parsers/parsers/innotec"
	"github.com/abusix/inbound-parsers/parsers/interconnect"
	"github.com/abusix/inbound-parsers/parsers/interhost"
	"github.com/abusix/inbound-parsers/parsers/interieur_gouv_fr"
	"github.com/abusix/inbound-parsers/parsers/internet2"
	"github.com/abusix/inbound-parsers/parsers/intsights"
	"github.com/abusix/inbound-parsers/parsers/ionos"
	"github.com/abusix/inbound-parsers/parsers/ipvanish"
	"github.com/abusix/inbound-parsers/parsers/ipxo"
	"github.com/abusix/inbound-parsers/parsers/irdeto"
	"github.com/abusix/inbound-parsers/parsers/irisio"
	"github.com/abusix/inbound-parsers/parsers/irs"
	"github.com/abusix/inbound-parsers/parsers/isag"
	"github.com/abusix/inbound-parsers/parsers/ish"
	"github.com/abusix/inbound-parsers/parsers/iwf"
	"github.com/abusix/inbound-parsers/parsers/izoologic"
	"github.com/abusix/inbound-parsers/parsers/jcloud"
	"github.com/abusix/inbound-parsers/parsers/jeffv"
	"github.com/abusix/inbound-parsers/parsers/joturl"
	"github.com/abusix/inbound-parsers/parsers/jpcert"
	"github.com/abusix/inbound-parsers/parsers/jugendschutz"
	"github.com/abusix/inbound-parsers/parsers/juno"
	"github.com/abusix/inbound-parsers/parsers/jutho"
	"github.com/abusix/inbound-parsers/parsers/kilpatricktown"
	"github.com/abusix/inbound-parsers/parsers/kinghost"
	"github.com/abusix/inbound-parsers/parsers/kinopoisk"
	"github.com/abusix/inbound-parsers/parsers/klingler_net"
	"github.com/abusix/inbound-parsers/parsers/kpnmail"
	"github.com/abusix/inbound-parsers/parsers/laliga"
	"github.com/abusix/inbound-parsers/parsers/latam"
	"github.com/abusix/inbound-parsers/parsers/leakix"
	"github.com/abusix/inbound-parsers/parsers/leakserv"
	"github.com/abusix/inbound-parsers/parsers/leaseweb"
	"github.com/abusix/inbound-parsers/parsers/legalbaselaw"
	"github.com/abusix/inbound-parsers/parsers/limestone"
	"github.com/abusix/inbound-parsers/parsers/m247"
	"github.com/abusix/inbound-parsers/parsers/magazineluiza"
	"github.com/abusix/inbound-parsers/parsers/mail_abuse"
	"github.com/abusix/inbound-parsers/parsers/mail_bolster"
	"github.com/abusix/inbound-parsers/parsers/mail_reject"
	"github.com/abusix/inbound-parsers/parsers/mail_ru"
	"github.com/abusix/inbound-parsers/parsers/mailabuse"
	"github.com/abusix/inbound-parsers/parsers/manitu"
	"github.com/abusix/inbound-parsers/parsers/marche_be"
	"github.com/abusix/inbound-parsers/parsers/marf"
	"github.com/abusix/inbound-parsers/parsers/markscan"
	"github.com/abusix/inbound-parsers/parsers/marqvision"
	"github.com/abusix/inbound-parsers/parsers/masterdaweb"
	"github.com/abusix/inbound-parsers/parsers/mcgill"
	"github.com/abusix/inbound-parsers/parsers/meadowbrookequine"
	"github.com/abusix/inbound-parsers/parsers/mediastory"
	"github.com/abusix/inbound-parsers/parsers/meldpunkt_kinderporno"
	"github.com/abusix/inbound-parsers/parsers/melio"
	"github.com/abusix/inbound-parsers/parsers/michael_joost"
	"github.com/abusix/inbound-parsers/parsers/microsoft"
	"github.com/abusix/inbound-parsers/parsers/mieweb"
	"github.com/abusix/inbound-parsers/parsers/miglisoft"
	"github.com/abusix/inbound-parsers/parsers/mih_brandprotection"
	"github.com/abusix/inbound-parsers/parsers/mirrorimagegaming"
	"github.com/abusix/inbound-parsers/parsers/mm_moneygram"
	"github.com/abusix/inbound-parsers/parsers/mnemo"
	"github.com/abusix/inbound-parsers/parsers/mobsternet"
	"github.com/abusix/inbound-parsers/parsers/multimediallc"
	"github.com/abusix/inbound-parsers/parsers/mxtoolbox"
	"github.com/abusix/inbound-parsers/parsers/myloc"
	"github.com/abusix/inbound-parsers/parsers/nagramonitoring"
	"github.com/abusix/inbound-parsers/parsers/nagrastar"
	"github.com/abusix/inbound-parsers/parsers/names_uk"
	"github.com/abusix/inbound-parsers/parsers/nbcuni"
	"github.com/abusix/inbound-parsers/parsers/ncmec"
	"github.com/abusix/inbound-parsers/parsers/ncsc_fi"
	"github.com/abusix/inbound-parsers/parsers/ncsc"
	"github.com/abusix/inbound-parsers/parsers/neptus"
	"github.com/abusix/inbound-parsers/parsers/netbuild"
	"github.com/abusix/inbound-parsers/parsers/netcologne"
	"github.com/abusix/inbound-parsers/parsers/netcraft"
	"github.com/abusix/inbound-parsers/parsers/netis"
	"github.com/abusix/inbound-parsers/parsers/netresult"
	"github.com/abusix/inbound-parsers/parsers/netsecdb"
	"github.com/abusix/inbound-parsers/parsers/netum"
	"github.com/abusix/inbound-parsers/parsers/nfoservers"
	"github.com/abusix/inbound-parsers/parsers/nksc"
	"github.com/abusix/inbound-parsers/parsers/nla"
	"github.com/abusix/inbound-parsers/parsers/notificationofinfringement"
	"github.com/abusix/inbound-parsers/parsers/nsc"
	"github.com/abusix/inbound-parsers/parsers/nt_gov"
	"github.com/abusix/inbound-parsers/parsers/ntt"
	"github.com/abusix/inbound-parsers/parsers/nwf"
	"github.com/abusix/inbound-parsers/parsers/nyx"
	"github.com/abusix/inbound-parsers/parsers/obp_corsearch"
	"github.com/abusix/inbound-parsers/parsers/octopusdns"
	"github.com/abusix/inbound-parsers/parsers/onecloud"
	"github.com/abusix/inbound-parsers/parsers/onsist"
	"github.com/abusix/inbound-parsers/parsers/oplium"
	"github.com/abusix/inbound-parsers/parsers/oppl"
	"github.com/abusix/inbound-parsers/parsers/opsec_enforcements"
	"github.com/abusix/inbound-parsers/parsers/opsec_protect"
	"github.com/abusix/inbound-parsers/parsers/opsecsecurityonline"
	"github.com/abusix/inbound-parsers/parsers/orange_fr"
	"github.com/abusix/inbound-parsers/parsers/orange"
	"github.com/abusix/inbound-parsers/parsers/orangecyberdefense"
	"github.com/abusix/inbound-parsers/parsers/osn"
	"github.com/abusix/inbound-parsers/parsers/outlook"
	"github.com/abusix/inbound-parsers/parsers/outseer"
	"github.com/abusix/inbound-parsers/parsers/p44"
	"github.com/abusix/inbound-parsers/parsers/paps"
	"github.com/abusix/inbound-parsers/parsers/paramount"
	"github.com/abusix/inbound-parsers/parsers/pccc_trap"
	"github.com/abusix/inbound-parsers/parsers/pedohunt"
	"github.com/abusix/inbound-parsers/parsers/penega"
	"github.com/abusix/inbound-parsers/parsers/perfettivanmelle"
	"github.com/abusix/inbound-parsers/parsers/perso"
	"github.com/abusix/inbound-parsers/parsers/phishfort"
	"github.com/abusix/inbound-parsers/parsers/phishlabscom"
	"github.com/abusix/inbound-parsers/parsers/phoenixadvocates"
	"github.com/abusix/inbound-parsers/parsers/phototakedown"
	"github.com/abusix/inbound-parsers/parsers/pj3cx"
	"github.com/abusix/inbound-parsers/parsers/profihost"
	"github.com/abusix/inbound-parsers/parsers/project_honeypot_trap"
	"github.com/abusix/inbound-parsers/parsers/promusicae"
	"github.com/abusix/inbound-parsers/parsers/prsformusic"
	"github.com/abusix/inbound-parsers/parsers/puglia"
	"github.com/abusix/inbound-parsers/parsers/puig"
	"github.com/abusix/inbound-parsers/parsers/pwn2_zip"
	"github.com/abusix/inbound-parsers/parsers/qwertynetworks"
	"github.com/abusix/inbound-parsers/parsers/rapid7"
	"github.com/abusix/inbound-parsers/parsers/react"
	"github.com/abusix/inbound-parsers/parsers/realityripple"
	"github.com/abusix/inbound-parsers/parsers/redfish"
	"github.com/abusix/inbound-parsers/parsers/rediffmail_tis"
	"github.com/abusix/inbound-parsers/parsers/redpoints"
	"github.com/abusix/inbound-parsers/parsers/reggerspaul"
	"github.com/abusix/inbound-parsers/parsers/regioconnect"
	"github.com/abusix/inbound-parsers/parsers/registro"
	"github.com/abusix/inbound-parsers/parsers/removal_request"
	"github.com/abusix/inbound-parsers/parsers/revengepornhelpline"
	"github.com/abusix/inbound-parsers/parsers/riaa"
	"github.com/abusix/inbound-parsers/parsers/richardwebley"
	"github.com/abusix/inbound-parsers/parsers/ricomanagement"
	"github.com/abusix/inbound-parsers/parsers/riskiq"
	"github.com/abusix/inbound-parsers/parsers/rivertec"
	"github.com/abusix/inbound-parsers/parsers/rsjaffe"
	"github.com/abusix/inbound-parsers/parsers/ruprotect"
	"github.com/abusix/inbound-parsers/parsers/sakura"
	"github.com/abusix/inbound-parsers/parsers/savana"
	"github.com/abusix/inbound-parsers/parsers/sbcglobal"
	"github.com/abusix/inbound-parsers/parsers/scert"
	"github.com/abusix/inbound-parsers/parsers/secureserver"
	"github.com/abusix/inbound-parsers/parsers/selcloud"
	"github.com/abusix/inbound-parsers/parsers/serverplan"
	"github.com/abusix/inbound-parsers/parsers/serverstack"
	"github.com/abusix/inbound-parsers/parsers/serviceexpress"
	"github.com/abusix/inbound-parsers/parsers/shadowserver_digest"
	"github.com/abusix/inbound-parsers/parsers/shadowserver"
	"github.com/abusix/inbound-parsers/parsers/shinhan"
	"github.com/abusix/inbound-parsers/parsers/sia"
	"github.com/abusix/inbound-parsers/parsers/sidnnl"
	"github.com/abusix/inbound-parsers/parsers/simple_format"
	"github.com/abusix/inbound-parsers/parsers/simple_guess_parser"
	"github.com/abusix/inbound-parsers/parsers/simple_rewrite"
	"github.com/abusix/inbound-parsers/parsers/simple_tis"
	"github.com/abusix/inbound-parsers/parsers/simple_url_report"
	"github.com/abusix/inbound-parsers/parsers/skhron"
	"github.com/abusix/inbound-parsers/parsers/sony"
	"github.com/abusix/inbound-parsers/parsers/spamcop"
	"github.com/abusix/inbound-parsers/parsers/spamhaus"
	"github.com/abusix/inbound-parsers/parsers/squarespace"
	"github.com/abusix/inbound-parsers/parsers/stackpath"
	"github.com/abusix/inbound-parsers/parsers/staxogroup"
	"github.com/abusix/inbound-parsers/parsers/stockpile"
	"github.com/abusix/inbound-parsers/parsers/stop_or_kr"
	"github.com/abusix/inbound-parsers/parsers/storage_base"
	"github.com/abusix/inbound-parsers/parsers/streamenforcement"
	"github.com/abusix/inbound-parsers/parsers/studiobarbero"
	"github.com/abusix/inbound-parsers/parsers/svbuero"
	"github.com/abusix/inbound-parsers/parsers/swisscom_tis"
	"github.com/abusix/inbound-parsers/parsers/swisscom"
	"github.com/abusix/inbound-parsers/parsers/switchch"
	"github.com/abusix/inbound-parsers/parsers/synacor"
	"github.com/abusix/inbound-parsers/parsers/systeam"
	"github.com/abusix/inbound-parsers/parsers/takedown"
	"github.com/abusix/inbound-parsers/parsers/takedownnow"
	"github.com/abusix/inbound-parsers/parsers/takedownreporting"
	"github.com/abusix/inbound-parsers/parsers/tampabay"
	"github.com/abusix/inbound-parsers/parsers/tassilosturm"
	"github.com/abusix/inbound-parsers/parsers/tecban"
	"github.com/abusix/inbound-parsers/parsers/techspace"
	"github.com/abusix/inbound-parsers/parsers/telecentras"
	"github.com/abusix/inbound-parsers/parsers/telecom_tm"
	"github.com/abusix/inbound-parsers/parsers/telecomitalia"
	"github.com/abusix/inbound-parsers/parsers/telenor"
	"github.com/abusix/inbound-parsers/parsers/telus"
	"github.com/abusix/inbound-parsers/parsers/tempest"
	"github.com/abusix/inbound-parsers/parsers/terra"
	"github.com/abusix/inbound-parsers/parsers/tescobrandprotection"
	"github.com/abusix/inbound-parsers/parsers/themccandlessgroup"
	"github.com/abusix/inbound-parsers/parsers/thiscompany"
	"github.com/abusix/inbound-parsers/parsers/thomsentrampedach"
	"github.com/abusix/inbound-parsers/parsers/threeantsds"
	"github.com/abusix/inbound-parsers/parsers/tikaj"
	"github.com/abusix/inbound-parsers/parsers/timbrasil"
	"github.com/abusix/inbound-parsers/parsers/tmclo"
	"github.com/abusix/inbound-parsers/parsers/tntelecom"
	"github.com/abusix/inbound-parsers/parsers/torrent_markmonitor"
	"github.com/abusix/inbound-parsers/parsers/triciafox"
	"github.com/abusix/inbound-parsers/parsers/truelite"
	"github.com/abusix/inbound-parsers/parsers/trustpilot"
	"github.com/abusix/inbound-parsers/parsers/ttp_law"
	"github.com/abusix/inbound-parsers/parsers/tts_stuttgart"
	"github.com/abusix/inbound-parsers/parsers/tucows"
	"github.com/abusix/inbound-parsers/parsers/tvb"
	"github.com/abusix/inbound-parsers/parsers/tx_rr"
	"github.com/abusix/inbound-parsers/parsers/uceprotect"
	"github.com/abusix/inbound-parsers/parsers/ucr_edu"
	"github.com/abusix/inbound-parsers/parsers/ucs_br"
	"github.com/abusix/inbound-parsers/parsers/ufrgs"
	"github.com/abusix/inbound-parsers/parsers/ukie"
	"github.com/abusix/inbound-parsers/parsers/ukrbit"
	"github.com/abusix/inbound-parsers/parsers/uni_koblenz"
	"github.com/abusix/inbound-parsers/parsers/uphf"
	"github.com/abusix/inbound-parsers/parsers/urlhaus"
	"github.com/abusix/inbound-parsers/parsers/us_cert"
	"github.com/abusix/inbound-parsers/parsers/valentinobrandprotection"
	"github.com/abusix/inbound-parsers/parsers/verifrom"
	"github.com/abusix/inbound-parsers/parsers/verizon"
	"github.com/abusix/inbound-parsers/parsers/viaccessorca"
	"github.com/abusix/inbound-parsers/parsers/virtus"
	"github.com/abusix/inbound-parsers/parsers/vmware"
	"github.com/abusix/inbound-parsers/parsers/vobileinc"
	"github.com/abusix/inbound-parsers/parsers/vpsnet"
	"github.com/abusix/inbound-parsers/parsers/watchdog"
	"github.com/abusix/inbound-parsers/parsers/web"
	"github.com/abusix/inbound-parsers/parsers/webcapio"
	"github.com/abusix/inbound-parsers/parsers/webhostabusereporting"
	"github.com/abusix/inbound-parsers/parsers/websheriff"
	"github.com/abusix/inbound-parsers/parsers/websteiner"
	"github.com/abusix/inbound-parsers/parsers/websumo"
	"github.com/abusix/inbound-parsers/parsers/webtoonguide"
	"github.com/abusix/inbound-parsers/parsers/weightechinc"
	"github.com/abusix/inbound-parsers/parsers/whitefoxboutique"
	"github.com/abusix/inbound-parsers/parsers/winterburn"
	"github.com/abusix/inbound-parsers/parsers/winvoice"
	"github.com/abusix/inbound-parsers/parsers/wisc"
	"github.com/abusix/inbound-parsers/parsers/xarf"
	"github.com/abusix/inbound-parsers/parsers/xtakedowns"
	"github.com/abusix/inbound-parsers/parsers/yahoo"
	"github.com/abusix/inbound-parsers/parsers/ybrandprotection"
	"github.com/abusix/inbound-parsers/parsers/zap_hosting"
	"github.com/abusix/inbound-parsers/parsers/zapret"
	"github.com/abusix/inbound-parsers/parsers/zero_spam"
	"github.com/abusix/inbound-parsers/parsers/zerofox"
	"github.com/abusix/inbound-parsers/parsers/zohocorp"
)

// ParserWrapper wraps a parser with its priority
type ParserWrapper struct {
	Parser   base.Parser
	Priority int
}

// AllParsers returns all available parsers sorted by priority
func AllParsers() []ParserWrapper {
	parsers := []ParserWrapper{
		{Parser: &abuse_oneprovider.Parser{}},
		{Parser: &abusehub_nl.Parser{}},
		{Parser: &abusetrue_nl.Parser{}},
		{Parser: &abusix.Parser{}},
		{Parser: &acastano.Parser{}},
		{Parser: &accenture.Parser{}},
		{Parser: &acedatacenter.Parser{}},
		{Parser: &acns.Parser{}},
		{Parser: &adciberespaco.Parser{}},
		{Parser: &agouros.Parser{}},
		{Parser: &aiplex.Parser{}},
		{Parser: &akamai.Parser{}},
		{Parser: &amasha.Parser{}},
		{Parser: &amazon.Parser{}},
		{Parser: &antipiracy_report.Parser{}},
		{Parser: &antipiracy.Parser{}},
		{Parser: &antipiracyprotection.Parser{}},
		{Parser: &anvisa_gov.Parser{}},
		{Parser: &aol.Parser{}},
		{Parser: &ap_markmonitor.Parser{}},
		{Parser: &aparlay.Parser{}},
		{Parser: &apiccopyright.Parser{}},
		{Parser: &arkadruk.Parser{}},
		{Parser: &artplanet.Parser{}},
		{Parser: &aruba.Parser{}},
		{Parser: &att.Parser{}},
		{Parser: &attributor.Parser{}},
		{Parser: &autofusion.Parser{}},
		{Parser: &avoxi.Parser{}},
		{Parser: &axghouse.Parser{}},
		{Parser: &axur.Parser{}},
		{Parser: &b_monitor.Parser{}},
		{Parser: &barrettlawgroup.Parser{}},
		{Parser: &baysidecorp.Parser{}},
		{Parser: &bb.Parser{}},
		{Parser: &bbc.Parser{}},
		{Parser: &bellsouth.Parser{}},
		{Parser: &beygoo.Parser{}},
		{Parser: &bibo.Parser{}},
		{Parser: &bitninja.Parser{}},
		{Parser: &bka.Parser{}},
		{Parser: &black_dura.Parser{}},
		{Parser: &bluevoyant.Parser{}},
		{Parser: &bnshosting.Parser{}},
		{Parser: &bofa.Parser{}},
		{Parser: &botnet_tracker.Parser{}},
		{Parser: &bp_corsearch.Parser{}},
		{Parser: &bradesco.Parser{}},
		{Parser: &brandmonitor.Parser{}},
		{Parser: &brandprotection.Parser{}},
		{Parser: &brandsecurity_ru.Parser{}},
		{Parser: &brandshield.Parser{}},
		{Parser: &bsi.Parser{}},
		{Parser: &bt.Parser{}},
		{Parser: &buerki.Parser{}},
		{Parser: &buycheaprdp.Parser{}},
		{Parser: &bwbmodels.Parser{}},
		{Parser: &bytescare.Parser{}},
		{Parser: &cammodelprotect.Parser{}},
		{Parser: &cavac.Parser{}},
		{Parser: &ccirc.Parser{}},
		{Parser: &cdar_westpac.Parser{}},
		{Parser: &centurylink.Parser{}},
		{Parser: &centurylinkservices.Parser{}},
		{Parser: &cert_bz.Parser{}},
		{Parser: &cert_ee.Parser{}},
		{Parser: &cert_es.Parser{}},
		{Parser: &cert_gib.Parser{}},
		{Parser: &cert_gov.Parser{}},
		{Parser: &cert_hr.Parser{}},
		{Parser: &cert_in.Parser{}},
		{Parser: &cert_lt.Parser{}},
		{Parser: &cert_no.Parser{}},
		{Parser: &cert_nz.Parser{}},
		{Parser: &cert_pl.Parser{}},
		{Parser: &cert_pt.Parser{}},
		{Parser: &cert_rcts.Parser{}},
		{Parser: &cert_ro.Parser{}},
		{Parser: &cert_ua.Parser{}},
		{Parser: &certat.Parser{}},
		{Parser: &certbr.Parser{}},
		{Parser: &chaturbate.Parser{}},
		{Parser: &checkphish.Parser{}},
		{Parser: &circllu.Parser{}},
		{Parser: &ciu_online.Parser{}},
		{Parser: &cloudflare.Parser{}},
		{Parser: &cloudns.Parser{}},
		{Parser: &cnsd_gob_pe.Parser{}},
		{Parser: &cogent.Parser{}},
		{Parser: &colocationamerica.Parser{}},
		{Parser: &columbiaedu.Parser{}},
		{Parser: &comcast.Parser{}},
		{Parser: &comeso.Parser{}},
		{Parser: &communicationvalley.Parser{}},
		{Parser: &comvive.Parser{}},
		{Parser: &copyright_compliance.Parser{}},
		{Parser: &copyright_integrity.Parser{}},
		{Parser: &counterfeittechnology.Parser{}},
		{Parser: &courbis.Parser{}},
		{Parser: &courts_in.Parser{}},
		{Parser: &cpanel.Parser{}},
		{Parser: &cpragency.Parser{}},
		{Parser: &crdflabs.Parser{}},
		{Parser: &crm_wix.Parser{}},
		{Parser: &crowdstrike.Parser{}},
		{Parser: &csa.Parser{}},
		{Parser: &cscglobal.Parser{}},
		{Parser: &csirt_br.Parser{}},
		{Parser: &csirt_cz.Parser{}},
		{Parser: &csirt_divd.Parser{}},
		{Parser: &csirt_dnofd.Parser{}},
		{Parser: &csirt_muni.Parser{}},
		{Parser: &csis.Parser{}},
		{Parser: &customvisuals.Parser{}},
		{Parser: &cyber_gc.Parser{}},
		{Parser: &cyber999.Parser{}},
		{Parser: &cyberint.Parser{}},
		{Parser: &cybertip.Parser{}},
		{Parser: &cyberweb.Parser{}},
		{Parser: &cyble.Parser{}},
		{Parser: &d3lab.Parser{}},
		{Parser: &darklist.Parser{}},
		{Parser: &datapacket.Parser{}},
		{Parser: &dcpmail.Parser{}},
		{Parser: &dd_tech.Parser{}},
		{Parser: &ddos_google.Parser{}},
		{Parser: &debian.Parser{}},
		{Parser: &defaria.Parser{}},
		{Parser: &deft.Parser{}},
		{Parser: &deloite.Parser{}},
		{Parser: &desmoweb.Parser{}},
		{Parser: &dgn.Parser{}},
		{Parser: &dgt.Parser{}},
		{Parser: &digiguardians.Parser{}},
		{Parser: &digiturk.Parser{}},
		{Parser: &disney.Parser{}},
		{Parser: &djr_co.Parser{}},
		{Parser: &dmarc_xml.Parser{}},
		{Parser: &dmca_com.Parser{}},
		{Parser: &dmca_pro.Parser{}},
		{Parser: &dmcaforce.Parser{}},
		{Parser: &dmcapiracyprevention.Parser{}},
		{Parser: &dnainternet.Parser{}},
		{Parser: &dnsc.Parser{}},
		{Parser: &docusign.Parser{}},
		{Parser: &domainabusereporting.Parser{}},
		{Parser: &domainoo.Parser{}},
		{Parser: &doppel.Parser{}},
		{Parser: &dreamworldpartners.Parser{}},
		{Parser: &dreyfus.Parser{}},
		{Parser: &easysol.Parser{}},
		{Parser: &ebay.Parser{}},
		{Parser: &ebrand.Parser{}},
		{Parser: &ebs.Parser{}},
		{Parser: &eca.Parser{}},
		{Parser: &ecucert.Parser{}},
		{Parser: &eisys.Parser{}},
		{Parser: &ellematthewsmodel.Parser{}},
		{Parser: &enf_meta.Parser{}},
		{Parser: &enfappdetex.Parser{}},
		{Parser: &entura.Parser{}},
		{Parser: &ephemeron.Parser{}},
		{Parser: &eq_ee.Parser{}},
		{Parser: &esp.Parser{}},
		{Parser: &espresso.Parser{}},
		{Parser: &etoolkit.Parser{}},
		{Parser: &etotalhost.Parser{}},
		{Parser: &europa_eu.Parser{}},
		{Parser: &exemail.Parser{}},
		{Parser: &experian.Parser{}},
		{Parser: &expressvpn.Parser{}},
		{Parser: &eyeonpiracy.Parser{}},
		{Parser: &facct.Parser{}},
		{Parser: &fail2ban.Parser{}},
		{Parser: &fbi_ipv6home.Parser{}},
		{Parser: &fbs.Parser{}},
		{Parser: &feedback_loop.Parser{}},
		{Parser: &fhs.Parser{}},
		{Parser: &flyhosting.Parser{}},
		{Parser: &fmtsoperation.Parser{}},
		{Parser: &fondia.Parser{}},
		{Parser: &fraudwatch.Parser{}},
		{Parser: &fraudwatchinternational.Parser{}},
		{Parser: &freedomtech.Parser{}},
		{Parser: &friendmts.Parser{}},
		{Parser: &fsec.Parser{}},
		{Parser: &fsm.Parser{}},
		{Parser: &gastecnologia.Parser{}},
		{Parser: &generic_spam_trap.Parser{}},
		{Parser: &ginernet.Parser{}},
		{Parser: &giorgioarmaniweb.Parser{}},
		{Parser: &gmail_parser.Parser{}},
		{Parser: &gmx_com.Parser{}},
		{Parser: &gmx.Parser{}},
		{Parser: &gold_parser.Parser{}},
		{Parser: &googlesafebrowsing.Parser{}},
		{Parser: &govcert_ch.Parser{}},
		{Parser: &griffeshield.Parser{}},
		{Parser: &group_ib.Parser{}},
		{Parser: &hack_hunt.Parser{}},
		{Parser: &heficed.Parser{}},
		{Parser: &herrbischoff.Parser{}},
		{Parser: &hetzner.Parser{}},
		{Parser: &hfmarket.Parser{}},
		{Parser: &hispasec.Parser{}},
		{Parser: &hkcert.Parser{}},
		{Parser: &home.Parser{}},
		{Parser: &honeypots_tk.Parser{}},
		{Parser: &hostdime.Parser{}},
		{Parser: &hosteurope.Parser{}},
		{Parser: &hostfission.Parser{}},
		{Parser: &hostopia.Parser{}},
		{Parser: &hostroyale.Parser{}},
		{Parser: &hotmail.Parser{}},
		{Parser: &humongoushibiscus.Parser{}},
		{Parser: &hyperfilter.Parser{}},
		{Parser: &ibcom.Parser{}},
		{Parser: &ibm.Parser{}},
		{Parser: &icscards.Parser{}},
		{Parser: &ifpi.Parser{}},
		{Parser: &iheatwithoil.Parser{}},
		{Parser: &ilvasapolli.Parser{}},
		{Parser: &inaxas.Parser{}},
		{Parser: &incopro.Parser{}},
		{Parser: &infringements_cc.Parser{}},
		{Parser: &innotec.Parser{}},
		{Parser: &interconnect.Parser{}},
		{Parser: &interhost.Parser{}},
		{Parser: &interieur_gouv_fr.Parser{}},
		{Parser: &internet2.Parser{}},
		{Parser: &intsights.Parser{}},
		{Parser: &ionos.Parser{}},
		{Parser: &ipvanish.Parser{}},
		{Parser: &ipxo.Parser{}},
		{Parser: &irdeto.Parser{}},
		{Parser: &irisio.Parser{}},
		{Parser: &irs.Parser{}},
		{Parser: &isag.Parser{}},
		{Parser: &ish.Parser{}},
		{Parser: &iwf.Parser{}},
		{Parser: &izoologic.Parser{}},
		{Parser: &jcloud.Parser{}},
		{Parser: &jeffv.Parser{}},
		{Parser: &joturl.Parser{}},
		{Parser: &jpcert.Parser{}},
		{Parser: &jugendschutz.Parser{}},
		{Parser: &juno.Parser{}},
		{Parser: &jutho.Parser{}},
		{Parser: &kilpatricktown.Parser{}},
		{Parser: &kinghost.Parser{}},
		{Parser: &kinopoisk.Parser{}},
		{Parser: &klingler_net.Parser{}},
		{Parser: &kpnmail.Parser{}},
		{Parser: &laliga.Parser{}},
		{Parser: &latam.Parser{}},
		{Parser: &leakix.Parser{}},
		{Parser: &leakserv.Parser{}},
		{Parser: &leaseweb.Parser{}},
		{Parser: &legalbaselaw.Parser{}},
		{Parser: &limestone.Parser{}},
		{Parser: &m247.Parser{}},
		{Parser: &magazineluiza.Parser{}},
		{Parser: &mail_abuse.Parser{}},
		{Parser: &mail_bolster.Parser{}},
		{Parser: &mail_reject.Parser{}},
		{Parser: &mail_ru.Parser{}},
		{Parser: &mailabuse.Parser{}},
		{Parser: &manitu.Parser{}},
		{Parser: &marche_be.Parser{}},
		{Parser: &marf.Parser{}},
		{Parser: &markscan.Parser{}},
		{Parser: &marqvision.Parser{}},
		{Parser: &masterdaweb.Parser{}},
		{Parser: &mcgill.Parser{}},
		{Parser: &meadowbrookequine.Parser{}},
		{Parser: &mediastory.Parser{}},
		{Parser: &meldpunkt_kinderporno.Parser{}},
		{Parser: &melio.Parser{}},
		{Parser: &michael_joost.Parser{}},
		{Parser: &microsoft.Parser{}},
		{Parser: &mieweb.Parser{}},
		{Parser: &miglisoft.Parser{}},
		{Parser: &mih_brandprotection.Parser{}},
		{Parser: &mirrorimagegaming.Parser{}},
		{Parser: &mm_moneygram.Parser{}},
		{Parser: &mnemo.Parser{}},
		{Parser: &mobsternet.Parser{}},
		{Parser: &multimediallc.Parser{}},
		{Parser: &mxtoolbox.Parser{}},
		{Parser: &myloc.Parser{}},
		{Parser: &nagramonitoring.Parser{}},
		{Parser: &nagrastar.Parser{}},
		{Parser: &names_uk.Parser{}},
		{Parser: &nbcuni.Parser{}},
		{Parser: &ncmec.Parser{}},
		{Parser: &ncsc_fi.Parser{}},
		{Parser: &ncsc.Parser{}},
		{Parser: &neptus.Parser{}},
		{Parser: &netbuild.Parser{}},
		{Parser: &netcologne.Parser{}},
		{Parser: &netcraft.Parser{}},
		{Parser: &netis.Parser{}},
		{Parser: &netresult.Parser{}},
		{Parser: &netsecdb.Parser{}},
		{Parser: &netum.Parser{}},
		{Parser: &nfoservers.Parser{}},
		{Parser: &nksc.Parser{}},
		{Parser: &nla.Parser{}},
		{Parser: &notificationofinfringement.Parser{}},
		{Parser: &nsc.Parser{}},
		{Parser: &nt_gov.Parser{}},
		{Parser: &ntt.Parser{}},
		{Parser: &nwf.Parser{}},
		{Parser: &nyx.Parser{}},
		{Parser: &obp_corsearch.Parser{}},
		{Parser: &octopusdns.Parser{}},
		{Parser: &onecloud.Parser{}},
		{Parser: &onsist.Parser{}},
		{Parser: &oplium.Parser{}},
		{Parser: &oppl.Parser{}},
		{Parser: &opsec_enforcements.Parser{}},
		{Parser: &opsec_protect.Parser{}},
		{Parser: &opsecsecurityonline.Parser{}},
		{Parser: &orange_fr.Parser{}},
		{Parser: &orange.Parser{}},
		{Parser: &orangecyberdefense.Parser{}},
		{Parser: &osn.Parser{}},
		{Parser: &outlook.Parser{}},
		{Parser: &outseer.Parser{}},
		{Parser: &p44.Parser{}},
		{Parser: &paps.Parser{}},
		{Parser: &paramount.Parser{}},
		{Parser: &pccc_trap.Parser{}},
		{Parser: &pedohunt.Parser{}},
		{Parser: &penega.Parser{}},
		{Parser: &perfettivanmelle.Parser{}},
		{Parser: &perso.Parser{}},
		{Parser: &phishfort.Parser{}},
		{Parser: &phishlabscom.Parser{}},
		{Parser: &phoenixadvocates.Parser{}},
		{Parser: &phototakedown.Parser{}},
		{Parser: &pj3cx.Parser{}},
		{Parser: &profihost.Parser{}},
		{Parser: &project_honeypot_trap.Parser{}},
		{Parser: &promusicae.Parser{}},
		{Parser: &prsformusic.Parser{}},
		{Parser: &puglia.Parser{}},
		{Parser: &puig.Parser{}},
		{Parser: &pwn2_zip.Parser{}},
		{Parser: &qwertynetworks.Parser{}},
		{Parser: &rapid7.Parser{}},
		{Parser: &react.Parser{}},
		{Parser: &realityripple.Parser{}},
		{Parser: &redfish.Parser{}},
		{Parser: &rediffmail_tis.Parser{}},
		{Parser: &redpoints.Parser{}},
		{Parser: &reggerspaul.Parser{}},
		{Parser: &regioconnect.Parser{}},
		{Parser: &registro.Parser{}},
		{Parser: &removal_request.Parser{}},
		{Parser: &revengepornhelpline.Parser{}},
		{Parser: &riaa.Parser{}},
		{Parser: &richardwebley.Parser{}},
		{Parser: &ricomanagement.Parser{}},
		{Parser: &riskiq.Parser{}},
		{Parser: &rivertec.Parser{}},
		{Parser: &rsjaffe.Parser{}},
		{Parser: &ruprotect.Parser{}},
		{Parser: &sakura.Parser{}},
		{Parser: &savana.Parser{}},
		{Parser: &sbcglobal.Parser{}},
		{Parser: &scert.Parser{}},
		{Parser: &secureserver.Parser{}},
		{Parser: &selcloud.Parser{}},
		{Parser: &serverplan.Parser{}},
		{Parser: &serverstack.Parser{}},
		{Parser: &serviceexpress.Parser{}},
		{Parser: &shadowserver_digest.Parser{}},
		{Parser: &shadowserver.Parser{}},
		{Parser: &shinhan.Parser{}},
		{Parser: &sia.Parser{}},
		{Parser: &sidnnl.Parser{}},
		{Parser: &simple_format.Parser{}},
		{Parser: &simple_guess_parser.Parser{}},
		{Parser: &simple_rewrite.Parser{}},
		{Parser: &simple_tis.Parser{}},
		{Parser: &simple_url_report.Parser{}},
		{Parser: &skhron.Parser{}},
		{Parser: &sony.Parser{}},
		{Parser: &spamcop.Parser{}},
		{Parser: &spamhaus.Parser{}},
		{Parser: &squarespace.Parser{}},
		{Parser: &stackpath.Parser{}},
		{Parser: &staxogroup.Parser{}},
		{Parser: &stockpile.Parser{}},
		{Parser: &stop_or_kr.Parser{}},
		{Parser: &storage_base.Parser{}},
		{Parser: &streamenforcement.Parser{}},
		{Parser: &studiobarbero.Parser{}},
		{Parser: &svbuero.Parser{}},
		{Parser: &swisscom_tis.Parser{}},
		{Parser: &swisscom.Parser{}},
		{Parser: &switchch.Parser{}},
		{Parser: &synacor.Parser{}},
		{Parser: &systeam.Parser{}},
		{Parser: &takedown.Parser{}},
		{Parser: &takedownnow.Parser{}},
		{Parser: &takedownreporting.Parser{}},
		{Parser: &tampabay.Parser{}},
		{Parser: &tassilosturm.Parser{}},
		{Parser: &tecban.Parser{}},
		{Parser: &techspace.Parser{}},
		{Parser: &telecentras.Parser{}},
		{Parser: &telecom_tm.Parser{}},
		{Parser: &telecomitalia.Parser{}},
		{Parser: &telenor.Parser{}},
		{Parser: &telus.Parser{}},
		{Parser: &tempest.Parser{}},
		{Parser: &terra.Parser{}},
		{Parser: &tescobrandprotection.Parser{}},
		{Parser: &themccandlessgroup.Parser{}},
		{Parser: &thiscompany.Parser{}},
		{Parser: &thomsentrampedach.Parser{}},
		{Parser: &threeantsds.Parser{}},
		{Parser: &tikaj.Parser{}},
		{Parser: &timbrasil.Parser{}},
		{Parser: &tmclo.Parser{}},
		{Parser: &tntelecom.Parser{}},
		{Parser: &torrent_markmonitor.Parser{}},
		{Parser: &triciafox.Parser{}},
		{Parser: &truelite.Parser{}},
		{Parser: &trustpilot.Parser{}},
		{Parser: &ttp_law.Parser{}},
		{Parser: &tts_stuttgart.Parser{}},
		{Parser: &tucows.Parser{}},
		{Parser: &tvb.Parser{}},
		{Parser: &tx_rr.Parser{}},
		{Parser: &uceprotect.Parser{}},
		{Parser: &ucr_edu.Parser{}},
		{Parser: &ucs_br.Parser{}},
		{Parser: &ufrgs.Parser{}},
		{Parser: &ukie.Parser{}},
		{Parser: &ukrbit.Parser{}},
		{Parser: &uni_koblenz.Parser{}},
		{Parser: &uphf.Parser{}},
		{Parser: &urlhaus.Parser{}},
		{Parser: &us_cert.Parser{}},
		{Parser: &valentinobrandprotection.Parser{}},
		{Parser: &verifrom.Parser{}},
		{Parser: &verizon.Parser{}},
		{Parser: &viaccessorca.Parser{}},
		{Parser: &virtus.Parser{}},
		{Parser: &vmware.Parser{}},
		{Parser: &vobileinc.Parser{}},
		{Parser: &vpsnet.Parser{}},
		{Parser: &watchdog.Parser{}},
		{Parser: &web.Parser{}},
		{Parser: &webcapio.Parser{}},
		{Parser: &webhostabusereporting.Parser{}},
		{Parser: &websheriff.Parser{}},
		{Parser: &websteiner.Parser{}},
		{Parser: &websumo.Parser{}},
		{Parser: &webtoonguide.Parser{}},
		{Parser: &weightechinc.Parser{}},
		{Parser: &whitefoxboutique.Parser{}},
		{Parser: &winterburn.Parser{}},
		{Parser: &winvoice.Parser{}},
		{Parser: &wisc.Parser{}},
		{Parser: &xarf.Parser{}},
		{Parser: &xtakedowns.Parser{}},
		{Parser: &yahoo.Parser{}},
		{Parser: &ybrandprotection.Parser{}},
		{Parser: &zap_hosting.Parser{}},
		{Parser: &zapret.Parser{}},
		{Parser: &zero_spam.Parser{}},
		{Parser: &zerofox.Parser{}},
		{Parser: &zohocorp.Parser{}},
	}

	// Set priorities from GetPriority() method
	for i := range parsers {
		parsers[i].Priority = parsers[i].Parser.GetPriority()
	}

	// Sort by priority (lower number = higher priority)
	sort.Slice(parsers, func(i, j int) bool {
		return parsers[i].Priority < parsers[j].Priority
	})

	return parsers
}

// ParseEmail parses an email using all registered parsers in priority order
func ParseEmail(serializedEmail *email.SerializedEmail, metadata map[string]interface{}) ([]*events.Event, error) {
	parsers := AllParsers()

	for _, pw := range parsers {
		events, err := pw.Parser.Parse(serializedEmail)
		if err == nil && len(events) > 0 {
			return events, nil
		}
		// Continue to next parser if this one failed or returned no events
	}

	return nil, nil // No parser matched
}
