# Parser Port Status - First 25 Parsers

## Summary

**Total Requested:** 25 parsers
**Completed:** 5 parsers
**Remaining:** 20 parsers (require significant additional work)

## Completed Parsers (5)

### 1. abusetrue_nl ✅
- **Location:** `/parsers/abusetrue_nl/abusetrue_nl.go`
- **Complexity:** Simple regex and pattern matching
- **Key Features:**
  - DDoS event detection
  - Date extraction from body
  - URL target parsing

### 2. abusix ✅
- **Location:** `/parsers/abusix/abusix.go`
- **Complexity:** CSV parsing
- **Key Features:**
  - CSV attachment processing
  - Compromised account events
  - Password hash extraction

### 3. acastano ✅
- **Location:** `/parsers/acastano/acastano.go`
- **Complexity:** Simple regex
- **Key Features:**
  - Malicious activity detection
  - Hostname extraction
  - IP extraction from subject

### 4. adciberespaco ✅
- **Location:** `/parsers/adciberespaco/adciberespaco.go`
- **Complexity:** Regex + HTML stripping
- **Key Features:**
  - HTML tag removal
  - Copyright event detection
  - Organization details extraction

### 5. agouros ✅
- **Location:** `/parsers/agouros/agouros.go`
- **Complexity:** Line-by-line parsing
- **Key Features:**
  - Login attack detection
  - Timezone handling
  - Tab-separated data parsing

## Parsers Requiring Additional Work (20)

### Complex Parsers (Require External Dependencies)

#### 1. abuse_oneprovider
- **Complexity:** HIGH
- **Dependencies:**
  - ACNS XML parsing (requires xmltodict equivalent)
  - Depends on acns.match() function
  - Warner Bros specific format parsing
- **Lines:** ~100
- **Status:** Stub only

#### 2. abusehub_nl
- **Complexity:** VERY HIGH
- **Dependencies:**
  - IODEF XML parsing (complex schema)
  - Shadowserver integration
  - Recursive attachment handling
  - Multiple event type detection
- **Lines:** ~200
- **Status:** Stub only

#### 3. acns
- **Complexity:** VERY HIGH
- **Dependencies:**
  - XML parsing with xmltodict
  - BeautifulSoup HTML parsing
  - File download from URLs
  - Complex nested XML structure
- **Lines:** ~300+
- **Status:** Stub only

#### 4. acedatacenter
- **Complexity:** HIGH
- **Dependencies:**
  - YAML parsing
  - XARF format (legacy)
  - Email rewriting/forwarding
  - Requires xarf parser module
- **Lines:** ~80
- **Status:** Stub only

#### 5. accenture
- **Complexity:** MEDIUM
- **Dependencies:**
  - Multiple regex patterns
  - Deep copy for event templates
  - Complex URL extraction
- **Lines:** ~127
- **Status:** Stub only

### Medium Complexity Parsers (Standard Processing)

#### 6. aiplex
- **Lines:** 127
- **Status:** Not started
- **Notes:** Likely copyright-related

#### 7. akamai
- **Lines:** 227
- **Status:** Not started
- **Notes:** Large parser, likely complex

#### 8. amasha
- **Lines:** 80
- **Status:** Not started

#### 9. amazon
- **Lines:** 54
- **Status:** Not started

#### 10. antipiracy
- **Lines:** 27
- **Status:** Not started
- **Notes:** Simple, good candidate

#### 11. antipiracy_report
- **Lines:** 22
- **Status:** Not started
- **Notes:** Simple, good candidate

#### 12. antipiracyprotection
- **Lines:** 49
- **Status:** Not started

#### 13. anvisa_gov
- **Lines:** 61
- **Status:** Not started

#### 14. aol
- **Lines:** 52
- **Status:** Not started

#### 15. ap_markmonitor
- **Lines:** 245
- **Status:** Not started
- **Notes:** Large, likely complex

#### 16. aparlay
- **Lines:** 49
- **Status:** Not started

#### 17. apiccopyright
- **Lines:** 62
- **Status:** Not started

#### 18. arkadruk
- **Lines:** 102
- **Status:** Not started

#### 19. artplanet
- **Lines:** 35
- **Status:** Not started
- **Notes:** Simple, good candidate

#### 20. aruba
- **Lines:** 81
- **Status:** Not started

## Issues Identified

### Missing Dependencies for Complex Parsers

1. **XML Parsing Libraries:**
   - Need Go equivalent of Python's `xmltodict`
   - IODEF schema support
   - XML entity handling

2. **HTML Parsing:**
   - Need Go equivalent of BeautifulSoup
   - Suggest: `golang.org/x/net/html` or `github.com/PuerkitoBio/goquery`

3. **YAML Parsing:**
   - Need `gopkg.in/yaml.v3`

4. **File Downloads:**
   - HTTP client with retry logic
   - Temporary file handling
   - ZIP file processing

5. **Additional Helper Functions Needed:**
   - `basic_event_copyright_parser()` - parses copyright data from body
   - `remove_html()` - HTML stripping with BR tag handling
   - `get_block_around()` - text extraction around markers
   - `find_string_without_markers()` - text extraction between markers
   - `get_line_after()` - line extraction after marker

## Recommendations

### Immediate Next Steps (Simple Parsers)

These parsers are simple enough to port quickly:

1. **antipiracy** (27 lines)
2. **antipiracy_report** (22 lines)
3. **artplanet** (35 lines)
4. **amazon** (54 lines)
5. **anvisa_gov** (61 lines)

### Before Tackling Complex Parsers

1. **Set up dependencies:**
   ```go
   go get golang.org/x/net/html
   go get github.com/PuerkitoBio/goquery
   go get gopkg.in/yaml.v3
   ```

2. **Implement missing helpers in `/parsers/common/`:**
   - `RemoveHTML()` with BR replacement
   - `BasicEventCopyrightParser()`
   - `DownloadFile()` with retry logic
   - `HandleZipPart()`

3. **Create shared XML parsers:**
   - ACNS/Infringement XML parser
   - IODEF parser
   - XARF parser

### Estimated Work Remaining

- **Simple parsers (5):** 2-3 hours
- **Medium parsers (10):** 8-12 hours
- **Complex parsers (5):** 15-20 hours
- **Helper functions:** 3-5 hours
- **Testing & debugging:** 10-15 hours

**Total:** ~40-55 hours of development work

## Files Created

```
/parsers/abusetrue_nl/abusetrue_nl.go
/parsers/abusix/abusix.go
/parsers/acastano/acastano.go
/parsers/adciberespaco/adciberespaco.go
/parsers/agouros/agouros.go
```

## Critical API Pattern Used

All parsers follow this pattern:

```go
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
    // Get body
    body, _ := common.GetBody(serializedEmail, false)

    // Get subject
    subject, _ := common.GetSubject(serializedEmail, false)

    // Create event
    event := events.NewEvent("parser_name")

    // Parse date
    eventDate := email.ParseDate(dateStr)
    event.EventDate = eventDate

    // Return
    return []*events.Event{event}, nil
}
```

## Next Session Recommendations

1. Port the 5 simple parsers listed above
2. Implement remaining common helper functions
3. Set up XML/HTML parsing dependencies
4. Create shared ACNS/IODEF parsers as separate packages
5. Then tackle the complex parsers one by one
