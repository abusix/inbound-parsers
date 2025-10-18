# Test Data

This directory contains test sample emails for parser validation.

## Structure

- `sample_mails/` - 2016 sample email files in `.eml` format
  - Organized by parser name: `[parser_name].[description].[number].eml`
  - 465 parsers have sample emails
  - 51 assertion files (`.assertions.py`) contain expected parsing results

## Sample Email Naming Convention

```
[parser_name].[description].[number].eml
```

Examples:
- `abuse_oneprovider.1.eml`
- `expressvpn.0.eml`
- `mail_reject.rejected.3.eml`

## Assertion Files

Some sample emails have corresponding `.assertions.py` files that define expected parsing results.

Example: `expressvpn.0.eml.assertions.py`

These files contain Python functions that verify:
- Number of events generated
- IP addresses extracted
- URLs found
- Event types
- Other parser-specific details

## Usage

Use these sample emails to verify Go parser implementations produce identical output to Python parsers.
