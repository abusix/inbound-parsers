# CRITICAL: Parser Audit Report - Fabricated Parsers Identified

**Date:** 2025-10-18  
**Project:** inbound-parsers (Go migration)  
**Auditor:** AI Flow / Claude Code  
**Status:** 🚨 CRITICAL FINDINGS

## Executive Summary

Out of **552 total Go parsers**, we have identified **64 parsers that appear to be FABRICATED** - they claim to parse emails from organizations but have NO corresponding Python source code in the original project.

### Overall Statistics

| Category | Count | Percentage | Description |
|----------|-------|------------|-------------|
| **VERIFIED** | 38 | 6.9% | Has Python source with explicit translation comment |
| **RENAMED** | 412 | 74.6% | Python source exists but missing/incorrect translation comments |
| **SUSPICIOUS (with Python)** | 36 | 6.5% | No translation comment but Python file was found |
| **🚨 FABRICATED** | 64 | 11.6% | **NO Python source exists - LIKELY FAKE** |
| **ERROR** | 2 | 0.4% | Could not read Go file |

## 🚨 CRITICAL: Likely Fabricated Parsers (64)

These parsers have **NO corresponding Python source** in the original project. They were likely created by AI without actual email samples to validate against.

### Cloud/Hosting Providers (19)
- **aws** - Amazon Web Services (claimed: abuse@amazonaws.com)
- **azure** - Microsoft Azure
- **gcp** - Google Cloud Platform
- **digital_ocean** - DigitalOcean
- **vultr** - Vultr
- **linode** - Linode
- **ovh** - OVH
- **scaleway** - Scaleway
- **rackspace** - Rackspace
- **bluehost** - Bluehost
- **dreamhost** - DreamHost
- **godaddy** - GoDaddy
- **choopa** - Choopa (now Vultr)
- **nocix** - NOCIX
- **psychz** - PsychZ Networks
- **quadranet** - QuadraNet
- **sharktech** - SharkTech
- **vpsville** - VPSVille
- **zenlayer** - Zenlayer

### ISPs & Telcos (9)
- **bell** - Bell Canada (similar to bellsouth.py exists)
- **rogers** - Rogers Communications
- **spectrum** - Spectrum/Charter
- **twc** - Time Warner Cable
- **korea_telecom** - Korea Telecom
- **lg_uplus** - LG U+
- **sk_broadband** - SK Broadband
- **kabel_deutschland** - Kabel Deutschland
- **unity_media** - Unity Media
- **versatel** - Versatel
- **strato** - Strato AG

### Media/Entertainment (10)
- **netflix** - Netflix (Pattern-based stub - NO real emails)
- **apple** - Apple Inc. (Pattern-based - NO real emails)
- **hbo** - HBO
- **cbs** - CBS
- **fox** - Fox Corporation
- **viacom** - ViacomCBS
- **mpaa** - Motion Picture Association
- **bpi** - British Phonographic Industry
- **itv** - ITV (UK broadcaster)
- **sky** - Sky Broadcasting

### Technology Companies (9)
- **facebook** - Facebook/Meta
- **instagram** - Instagram
- **twitter** - Twitter/X
- **linkedin** - LinkedIn
- **adobe** - Adobe
- **wordpress** - WordPress.com
- **shopify** - Shopify
- **wix** - Wix (crm_wix.py exists but different)
- **tencent** - Tencent
- **baidu** - Baidu
- **huawei** - Huawei

### DNS/Domain Services (4)
- **namecheap** - Namecheap
- **enom** - eNom
- **route53** - AWS Route53
- **dnsimple** - DNSimple

### Security/Threat Intel (2)
- **recordedfuture** - Recorded Future
- **paypal** - PayPal fraud/phishing

### Other Services (11)
- **etsy** - Etsy marketplace
- **fastly** - Fastly CDN
- **internap** - Internap
- **ecatel** - Ecatel
- **softlayer** - SoftLayer/IBM Cloud
- **packet** - Packet.net (datapacket.py exists)
- **oneandone** - 1&1
- **opsec_enforcements** - OpSec Enforcements
- **enf_meta** - Enforcement Meta
- **marche_be** - Marche Belgium
- **cert_fi** - CERT Finland (ncsc_fi.py exists)

## ⚠️ Pattern-Based Parsers (Fabricated Evidence)

Many of these parsers have telltale comments indicating they were created WITHOUT actual email samples:

```go
// Package apple implements the Apple Inc. brand protection parser
// Pattern-based implementation for Apple trademark/copyright reports

// Package netflix implements the netflix parser
// Pattern-based stub implementation (no Python source exists)

// Package aws implements the AWS (Amazon Web Services) abuse report parser
// Parser for AWS abuse notifications from abuse@amazonaws.com
```

These parsers **guess** at what the email format might look like based on:
- Generic patterns (IP address, URL, domain)
- Assumptions about sender email addresses
- Standard abuse report structures

**However**, without actual email samples from these organizations, we cannot verify:
1. Do they actually send abuse reports in this format?
2. Do they send abuse reports at all?
3. Are the sender addresses correct?
4. Are the extracted fields correct?

## ✅ Verified Parsers (38)

These have explicit Python source references and can be trusted:

```
abuse_ch -> urlhaus.py
abuse_oneprovider -> abuse_oneprovider.py
abusehub_nl -> abusehub_nl.py
abusetrue_nl -> abusetrue_nl.py
abusix -> abusix.py
accenture -> accenture.py
bellsouth -> bellsouth.py
botnet_tracker -> botnet_tracker.py
cloudns -> cloudns.py
comcast -> comcast.py
ebay -> ebay.py
fbl -> 02_feedback_loop.py
ifpi -> ifpi.py
ionos -> ionos.py
leaseweb -> leaseweb.py
phishfort -> phishfort.py
spamcop -> spamcop.py
spamhaus -> spamhaus.py
verizon -> verizon.py
... (see /tmp/verified_parsers.txt)
```

## ⚠️ Renamed/Missing Comments (412)

These have Python sources but lack proper translation comments:
- All appear to be legitimate translations
- Need translation comments added for traceability
- See `/tmp/renamed_parsers.txt` for full list

## 🔍 Parsers with Similar Python Files (17 saved from "suspicious")

These were initially suspicious but have matching Python files:
- attributor -> attributor.py
- avoxi -> avoxi.py
- cyberint -> cyberint.py
- dmca_com -> dmca_com.py
- group_ib -> group_ib.py
- markscan -> markscan.py
- riskiq -> riskiq.py
- zerofox -> zerofox.py
... and others

## 🎯 Recommended Actions

### IMMEDIATE (Critical)

1. **REMOVE or QUARANTINE** all 64 fabricated parsers
2. **DO NOT DEPLOY** any of the fabricated parsers to production
3. **AUDIT TEST DATA** - Check if any tests exist for fabricated parsers
4. **REVIEW COMMIT HISTORY** - Identify when/how these were created

### SHORT TERM (High Priority)

1. **Add translation comments** to all 412 renamed parsers
2. **Verify functionality** of renamed parsers against Python originals
3. **Document** which organizations actually send abuse reports
4. **Create allowlist** of verified senders

### LONG TERM (Maintenance)

1. **Require evidence** before adding new parsers:
   - Actual email samples
   - Python source reference OR
   - Documented customer request with examples
2. **Add CI checks** to prevent parsers without Python sources
3. **Quality gate**: No parser without test data

## 📊 Risk Assessment

| Risk Level | Parser Count | Impact |
|------------|--------------|--------|
| 🔴 **CRITICAL** | 64 | May misclassify or fail to parse real abuse reports |
| 🟡 **MEDIUM** | 412 | Missing traceability (but likely functional) |
| 🟢 **LOW** | 38 | Verified and documented |

## 📁 Supporting Files

- `/tmp/suspicious_parsers.txt` - All 100 initially suspicious parsers
- `/tmp/verified_parsers.txt` - 38 confirmed verified parsers
- `/tmp/renamed_parsers.txt` - 412 parsers needing comments

## Conclusion

**We have a serious quality problem**: 64 parsers (11.6%) appear to be fabricated without actual email samples or Python source code. These parsers may:
- Never match any real emails
- Misparse real emails
- Give false confidence in abuse report handling

**Recommendation**: Immediately audit and remove fabricated parsers before production deployment.

---

**Generated:** 2025-10-18  
**Tool:** Claude Code / AI Flow  
**Repository:** /Users/tknecht/Projects/inbound-parsers
