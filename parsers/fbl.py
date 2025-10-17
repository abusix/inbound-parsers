"""
FBL (Feedback Loop) Parser - RFC 9477 Compliant CFBL Implementation

Extracted from abusix-parsers v1: abusix_parsers/parsers/parser/02_feedback_loop.py
Simplified for inbound-parsers v2 with Pydantic models.
"""

import base64
import re
from typing import Any, Dict, List, Optional

import dkim
import tldextract
from pydantic import BaseModel, Field


class ParserError(Exception):
    """Raised when parser encounters an error during processing"""

    pass


class FBLEvent(BaseModel):
    """Feedback Loop Event output model"""

    event_type: str = "feedback_loop"
    spam_type: str = "spam"
    ip: str
    url: str
    event_date: Optional[str] = None
    headers: Dict[str, List[str]]
    sample_payload: str = Field(..., description="Base64 encoded RFC822 message")
    sample_content_type: str = "message/rfc822"
    sample_encoding: str = "base64"


class EmailMessage(BaseModel):
    """Simplified email message model"""

    headers: Dict[str, List[str]]
    metadata: Dict[str, Any]
    parsed_message: Any  # Will be email.message.Message object
    parts: List[Dict[str, Any]] = []


def find_string_without_markers(value: str, startswith: str, endswith: str = "") -> str:
    """Extract substring between markers (without including the markers)"""
    if not endswith:
        endswith = "\n" if "\n" in value else "\r\n"

    start_idx = value.find(startswith)
    if start_idx == -1:
        return ""

    end_idx = value.find(endswith, start_idx + len(startswith))
    if end_idx == -1:
        return ""

    return value[start_idx + len(startswith) : end_idx]


def _find_valid_dkim_sig_for_domain(
    domain: str, auth_results: List[str], dkim_signatures: List[str], cfbl_address: str
) -> Optional[str]:
    """Find valid DKIM signature for a given domain"""
    found = False
    valid_dkim = ""

    for auth_result in auth_results:
        dkim_domain = find_string_without_markers(auth_result, "header.d=", " ")
        domain_comparison = tldextract.extract(domain).registered_domain
        dkim_comparison = tldextract.extract(dkim_domain).registered_domain

        if domain_comparison == dkim_comparison:
            found = True
            if "dkim=pass" not in auth_result:
                raise ParserError(f"DKIM Validation failed for {dkim_domain}")
            else:
                valid_dkim = dkim_domain

    if not found:
        return None

    # Get the correct dkim signature for the domain
    for dkim_sig in dkim_signatures:
        if f"d={valid_dkim};" in dkim_sig:
            return dkim_sig

    return None


def _verify_dkim_signs_cfbl(dkim_signature: str) -> bool:
    """Verify that DKIM signature signs CFBL-Address header"""
    if not dkim_signature:
        return False

    dkim_signature = dkim_signature.replace("\r\n\t", " ").replace("\n\t", " ")
    signed_headers = find_string_without_markers(dkim_signature, " h=", ";")
    return "CFBL-Address" in [x.strip() for x in signed_headers.split(":")]


def _verify(
    cfbl_domain: str,
    auth_results: List[str],
    from_domain: str,
    headers: Dict[str, List[str]],
    cfbl_address: str,
) -> None:
    """
    Verify CFBL DKIM signatures according to RFC 9477

    Implements three verification modes:
    - Strict: CFBL domain == From domain
    - Relaxed: CFBL domain is subdomain of From domain
    - Third-party: CFBL domain != From domain
    """
    base_domain = tldextract.extract(from_domain).registered_domain

    if cfbl_domain == from_domain:
        # Strict check per sec. 3.1.2 of RFC9477
        dkim_sig = _find_valid_dkim_sig_for_domain(
            cfbl_domain, auth_results, headers["dkim-signature"], cfbl_address
        )
        if not dkim_sig or not _verify_dkim_signs_cfbl(dkim_sig):
            raise ParserError(f"CFBL DKIM check (strict) failed for CFBL address domain {cfbl_domain}")

    elif cfbl_domain.endswith("." + base_domain):
        # Relaxed check per sec. 3.1.3 of RFC9477
        dkim_sig = _find_valid_dkim_sig_for_domain(
            from_domain, auth_results, headers["dkim-signature"], cfbl_address
        )
        if dkim_sig and _verify_dkim_signs_cfbl(dkim_sig):
            return

        # Try child domain
        dkim_sig = _find_valid_dkim_sig_for_domain(
            cfbl_domain, auth_results, headers["dkim-signature"], cfbl_address
        )
        if dkim_sig and _verify_dkim_signs_cfbl(dkim_sig):
            return

        raise ParserError(f"CFBL DKIM check (relaxed) failed for CFBL address domain {cfbl_domain}")

    else:
        # Third-party check per sec. 3.1.3 of RFC9477
        dkim_sig = _find_valid_dkim_sig_for_domain(
            from_domain, auth_results, headers["dkim-signature"], cfbl_address
        )
        dkim_sig_cfbl = _find_valid_dkim_sig_for_domain(
            cfbl_domain, auth_results, headers["dkim-signature"], cfbl_address
        )

        # Check for alignment
        if (
            dkim_sig
            and _verify_dkim_signs_cfbl(dkim_sig)
            and dkim_sig_cfbl
            and _verify_dkim_signs_cfbl(dkim_sig_cfbl)
        ):
            return

        # Providers may accept presigned messages (MUST NOT sign CFBL headers)
        if dkim_sig_cfbl and _verify_dkim_signs_cfbl(dkim_sig_cfbl) and not _verify_dkim_signs_cfbl(dkim_sig):
            return

        raise ParserError(f"CFBL DKIM check (third-party) failed for CFBL address domain {cfbl_domain}")


def _build_auth_results(original: Any, headers: Dict[str, List[str]]) -> List[str]:
    """Build authentication results by verifying DKIM signatures"""
    dkim_msg = dkim.DKIM(original.as_bytes())
    auth_results = []

    for i in range(len(headers["dkim-signature"])):
        try:
            dkim_result = dkim_msg.verify(idx=i)
        except dkim.ValidationError:
            dkim_result = False

        dkim_sig = headers["dkim-signature"][i]
        dkim_d = find_string_without_markers(dkim_sig, "d=", ";")
        dkim_s = find_string_without_markers(dkim_sig, "s=", ";")
        auth_results.append(f"dkim={'pass' if dkim_result else 'fail'} header.d={dkim_d} header.s={dkim_s}")

    return auth_results


def parse_fbl(email_message: EmailMessage, from_addr: str) -> Optional[FBLEvent]:
    """
    Parse FBL (Feedback Loop) email and extract event data

    Args:
        email_message: Parsed email message with headers and metadata
        from_addr: From address of the email

    Returns:
        FBLEvent if valid FBL email, None otherwise

    Raises:
        ParserError: If DKIM validation fails or required headers missing
    """
    serialized_email = {
        "headers": email_message.headers,
        "metadata": email_message.metadata,
        "parsed_message": email_message.parsed_message,
        "parts": email_message.parts,
    }

    # Get authentication results from metadata (added by Haraka)
    auth_results = serialized_email["metadata"].get("auth_header", "").split(";")[1:]

    # Check for CFBL-Address header
    has_cfbl_address = "cfbl-address" in serialized_email["headers"]
    unpacked = False

    if not has_cfbl_address:
        # Check embedded message/rfc822 parts
        for i, part in enumerate(serialized_email["parts"]):
            if "headers" in part and "cfbl-address" in part["headers"]:
                has_cfbl_address = True
                serialized_email["headers"] = part["headers"]
                from_addr = part["headers"].get("from", [from_addr])[0]
                unpacked = True

                if "authentication-results" in serialized_email["headers"] and any(
                    "dkim=pass" in auth_result and "header.d=" in auth_result
                    for auth_result in serialized_email["headers"]["authentication-results"]
                ):
                    auth_results = serialized_email["headers"]["authentication-results"][0].split(";")[1:]
                else:
                    original_message = serialized_email["parsed_message"].get_payload(i=i).get_payload(0)
                    serialized_email["parsed_message"] = original_message
                    auth_results = _build_auth_results(original_message, serialized_email["headers"])
                break

    if not has_cfbl_address:
        raise ParserError("NO_CFBL_ADDRESS: Email is not a valid FBL report")

    # Parse CFBL addresses
    cfbl_addrs = serialized_email["headers"]["cfbl-address"]
    cfbl_addresses = serialized_email["headers"]["cfbl-address"][0].split(";")

    if report_type := find_string_without_markers(cfbl_addrs[0] + ";", "report=", ";"):
        cfbl_addresses.pop()
    else:
        report_type = "arf"

    # Extract domains from CFBL addresses
    cfbl_domains = set()
    for cfbl_address in cfbl_addresses:
        for idx, addr in enumerate(cfbl_addrs):
            if email_match := re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", addr):
                cfbl_addrs[idx] = email_match.group()
                cfbl_domains.add(email_match.group().split("@", 2)[1])
            else:
                raise ParserError(f"CFBL_ADDRESS_INVALID: {cfbl_address}")

    if "auth_header" not in serialized_email["metadata"]:
        raise ParserError("NO_AUTH_HEADER: DKIM is required for CFBL")

    # Verify DKIM for each CFBL domain
    from_domain = from_addr.split("@", 2)[1]
    for cfbl_domain in cfbl_domains:
        _verify(cfbl_domain, auth_results, from_domain, serialized_email["headers"], cfbl_address)

    # Extract IP address
    event_ip = None
    for header in ("x-abusix-originating-ip", "x-client-src", "x-originating-ip"):
        try:
            event_ip = serialized_email["headers"][header][0]
            if event_ip:
                break
        except (ValueError, KeyError):
            pass

    if not event_ip:
        # Try to extract from Received headers
        received = serialized_email["headers"]["received"]
        guessed_header = received[1 if len(received) > 1 else 0]
        # Simplified IP extraction (would need proper implementation)
        ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        if match := re.search(ipv4_pattern, guessed_header.split("by")[0]):
            event_ip = match.group()

    if not event_ip:
        raise ParserError("NO_IP_FOUND: Could not extract IP address from headers")

    # Extract event date from Received headers
    event_date = None
    # Simplified date extraction (would need proper ReceivedHeader parser)

    # Build return path
    if unpacked:
        return_path = serialized_email["headers"].get("return-path", [])
    else:
        return_path = serialized_email["headers"].get(
            "return-path", [serialized_email["metadata"].get("envelope_from", "")]
        )

    # Build event headers
    event_headers = {
        "cfbl-address": serialized_email["headers"]["cfbl-address"],
        "cfbl-report-type": [report_type],
        "message-id": serialized_email["headers"].get("message-id", []),
        "return-path": return_path,
    }

    if "cfbl-feedback-id" in serialized_email["headers"]:
        event_headers["cfbl-feedback-id"] = serialized_email["headers"]["cfbl-feedback-id"]

    # Create FBL event
    return FBLEvent(
        ip=event_ip,
        url=from_domain,
        event_date=event_date,
        headers=event_headers,
        sample_payload=base64.b64encode(serialized_email["parsed_message"].as_bytes()).decode("ascii"),
    )
