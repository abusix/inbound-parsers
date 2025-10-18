# Session Handoff: Parser Implementation Project

**Date**: 2025-10-18
**Project**: inbound-parsers (Go migration from Python)
**Status**: Parser stubs created, implementation in progress

---

## CRITICAL: What You Need to Do

**YOUR TASK**: Implement ALL 477 email abuse report parsers by porting them from Python to Go.

**SUCCESS CRITERIA**:
- ALL 477 parsers must have complete logic (not stubs)
- ALL parsers must compile without errors
- Output must match Python 100% (will be tested against 1,845 test emails)

---

## Current Status

### ✅ COMPLETED
1. **477 parser stubs created** - All in `parsers/*/` directories with correct API
2. **1,845 test emails copied** - From Python project to `tests/data/sample_mails/`
3. **Project structure ready** - All supporting packages exist (events, common, base, email)

### ❌ NOT DONE
1. **0 parsers fully implemented** - All 477 are stubs that return "not yet implemented"
2. **main.go not updated** - Needs 477 parser registrations added
3. **No test framework** - Need Go vs Python comparison tests

---

## File Locations

```
PROJECT ROOT: /Users/tknecht/Projects/inbound-parsers/

PYTHON SOURCE (reference):
/tmp/abusix-parsers-old/abusix_parsers/parsers/parser/*.py

PARSER LIST (477 parsers):
/tmp/python_parsers_477.txt

GO PARSERS (stubs to implement):
parsers/*/[name].go

TEST EMAILS:
tests/data/sample_mails/*.eml
```

---

## Parser Implementation Pattern

### Current Stub Format
```go
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
    // TODO: Port logic from Python [name].py
    body, err := common.GetBody(serializedEmail, false)
    _ = body
    return nil, common.NewParserError("parser not yet implemented")
}
```

### Required Full Implementation
```go
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error) {
    // 1. Get email data
    body, err := common.GetBody(serializedEmail, false)
    if err != nil {
        return nil, err
    }
    subject, _ := common.GetSubject(serializedEmail, false)

    // 2. Create event
    event := events.NewEvent("parser_name")

    // 3. Port Python parsing logic line-by-line
    //    - Extract IPs: event.IP = "1.2.3.4"
    //    - Extract URLs: event.URL = "http://..."
    //    - Set event types: event.EventTypes = []events.EventType{events.NewCopyright()}
    //    - Parse dates: event.EventDate = email.ParseDate(dateStr)
    //    - Add details: event.AddEventDetail(&events.File{FileName: "x"})

    // 4. Return events
    return []*events.Event{event}, nil
}
```

---

## Step-by-Step Process

### FOR EACH PARSER:

1. **Read Python source**
   ```bash
   # Find the Python file (handles prefixes like 001_, ZX_, etc.)
   ls /tmp/abusix-parsers-old/abusix_parsers/parsers/parser/ | grep [parser_name]
   ```

2. **Understand the logic**
   - What event type? (Copyright, Spam, Phishing, etc.)
   - What fields are extracted? (IP, URL, dates, etc.)
   - What parsing patterns? (regex, text markers, CSV, XML, etc.)

3. **Implement in Go**
   - Port logic line-by-line
   - Use helper functions from `parsers/common/`
   - Use event types from `events/`

4. **Build and verify**
   ```bash
   go build ./parsers/[name]
   ```

5. **Mark progress**
   - Update TODO list
   - Track which parsers are done

---

## Available Helper Functions

### From `parsers/common/`:
```go
common.GetBody(email, throws bool) (string, error)
common.GetSubject(email, throws bool) (string, error)
common.ExtractOneIP(text string) string
common.IsIP(text string) string
common.FindStringWithoutMarkers(text, start, end string) string
common.GetNonEmptyLineAfter(text, marker string) string
common.RemoveCarriageReturn(s string) string
// More in parsers/common/helpers.go
```

### From `events/`:
```go
events.NewEvent(parserName string) *Event
events.NewCopyright() *Copyright
events.NewSpam() *Spam
events.NewPhishing() *Phishing
// More in events/event_types.go
```

### From `pkg/email/`:
```go
email.ParseDate(dateStr string) *time.Time  // Returns pointer, not error tuple!
```

---

## Implementation Strategy

### RECOMMENDED APPROACH:

**Batch Implementation** (100 parsers per session, 5 sessions total):

1. **Session 1**: Implement parsers 1-100
2. **Session 2**: Implement parsers 101-200
3. **Session 3**: Implement parsers 201-300
4. **Session 4**: Implement parsers 301-400
5. **Session 5**: Implement parsers 401-477 + final integration

### For each batch:
1. Use Task agents in parallel (10 agents × 10 parsers each)
2. Verify build after each batch
3. Fix any compilation errors
4. Mark progress in TODO

---

## Common Patterns in Python Parsers

### Pattern 1: Simple field extraction
```python
# Python
event.ip = extract_ip(body)
event.event_date = parse_date(date_str)

# Go equivalent
event.IP = common.ExtractOneIP(body)
event.EventDate = email.ParseDate(dateStr)
```

### Pattern 2: Regex extraction
```python
# Python
match = re.search(r'IP:\s*(\S+)', body)
if match:
    event.ip = match.group(1)

# Go equivalent
re := regexp.MustCompile(`IP:\s*(\S+)`)
if match := re.FindStringSubmatch(body); len(match) > 1 {
    event.IP = match[1]
}
```

### Pattern 3: Event types
```python
# Python
event.event_types = Copyright()

# Go equivalent
event.EventTypes = []events.EventType{events.NewCopyright()}
```

---

## Testing (After Implementation)

Once all parsers are implemented:

1. **Update main.go** - Add all 477 parser registrations
2. **Build verification** - `go build ./...`
3. **Create test harness** - Compare Go vs Python output
4. **Run against test emails** - All 1,845 .eml files
5. **Fix mismatches** - Iterate until 100% parity

---

## Known Issues & Gotchas

### ❌ WRONG (common mistakes):
```go
// DON'T: email.Parse() doesn't exist
msg := email.Parse(data)

// DON'T: ParseDate returns *time.Time, not (time.Time, error)
date, err := email.ParseDate(str)

// DON'T: Wrong package path
import "github.com/abusix/inbound-parsers/email"
```

### ✅ CORRECT:
```go
// DO: Use SerializedEmail struct directly
func (p *Parser) Parse(serializedEmail *email.SerializedEmail) ([]*events.Event, error)

// DO: ParseDate returns pointer
eventDate := email.ParseDate(dateStr) // *time.Time

// DO: Correct package path
import "github.com/abusix/inbound-parsers/pkg/email"
```

---

## Quick Start Commands

```bash
# Go to project root
cd /Users/tknecht/Projects/inbound-parsers

# Check parser count
ls -1d parsers/*/ | grep -v '/base/$' | grep -v '/common/$' | wc -l
# Should show: 477

# Check test email count
find tests/data/sample_mails -name "*.eml" | wc -l
# Should show: 1845

# Build all parsers (to find errors)
go build ./parsers/...

# Check how many are still stubs
grep -r "TODO: Port logic from Python" parsers/*/*.go | wc -l
# Currently: 477 (all are stubs)

# View parser list
cat /tmp/python_parsers_477.txt | head -20
```

---

## Success Metrics

Track these numbers as you progress:

- **Parsers implemented**: 0 / 477
- **Parsers compiling**: 477 / 477 (stubs compile)
- **Build status**: ✅ Stubs compile
- **Test coverage**: 0 / 1845 emails
- **Output parity**: 0% (need implementation first)

**TARGET**: All metrics at 100%

---

## URGENT: What to Do FIRST

1. **Implement first 100 parsers** from `/tmp/python_parsers_477.txt`
2. **Verify each batch of 10** builds successfully
3. **Update progress** in TODO list
4. **DO NOT** use agents that claim success without verification
5. **TEST** each parser by building it immediately after implementation

---

## Important Notes

- **NO FABRICATION**: Only port from actual Python source files
- **NO SHORTCUTS**: Every parser needs full logic, not placeholders
- **NO FALSE CLAIMS**: Verify compilation before marking as done
- **100% ACCURACY**: Output must match Python exactly

---

## Contact/Handoff

Previous session ended at: Parser implementation preparation
Next session should start at: Implementing parsers 1-100 systematically

**Files modified in previous session**:
- Created all 477 parser stubs
- Copied 1,845 test emails
- Fixed a few parser API errors (abusehub_nl, abusetrue_nl)

**Priority**: Implement all 477 parsers across multiple sessions (100 per session)
