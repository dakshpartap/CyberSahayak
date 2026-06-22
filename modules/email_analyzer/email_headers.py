# modules/email_analyzer/email_headers.py
# Extract and analyze all relevant email headers.
# Detects spoofing, header injection, routing anomalies.

import re
import socket
import logging
import email.message
from typing import Optional

from modules.email_analyzer.email_parser import (
    normalize_email_address,
    get_domain_from_email,
)

logger = logging.getLogger(__name__)


def extract_all_headers(msg: email.message.EmailMessage) -> dict:
    """Extract all email headers into a normalized dict."""
    headers = {}
    try:
        for key in msg.keys():
            k = key.lower()
            val = msg.get(key, "")
            if k in headers:
                # Multiple values for same header (e.g., Received)
                if isinstance(headers[k], list):
                    headers[k].append(val)
                else:
                    headers[k] = [headers[k], val]
            else:
                headers[k] = val
    except Exception as e:
        logger.warning(f"Header extraction error: {e}")
    return headers


def parse_from_header(msg: email.message.EmailMessage) -> dict:
    """Parse the From header into structured data."""
    raw = msg.get("From", "")
    display_name, email_addr = normalize_email_address(raw)
    domain = get_domain_from_email(email_addr)
    return {
        "raw": raw,
        "display_name": display_name,
        "email": email_addr,
        "domain": domain,
    }


def parse_reply_to(msg: email.message.EmailMessage) -> dict:
    """Parse Reply-To header."""
    raw = msg.get("Reply-To", "")
    if not raw:
        return {"raw": "", "email": "", "domain": ""}
    _, email_addr = normalize_email_address(raw)
    return {
        "raw": raw,
        "email": email_addr,
        "domain": get_domain_from_email(email_addr),
    }


def parse_envelope_sender(msg: email.message.EmailMessage) -> dict:
    """
    Parse envelope sender (Return-Path / X-Original-To / envelope-from).
    This is the actual SMTP MAIL FROM address.
    """
    raw = (
        msg.get("Return-Path", "")
        or msg.get("X-Envelope-From", "")
        or msg.get("Envelope-From", "")
    )
    raw = raw.strip().strip("<>")
    return {
        "raw": raw,
        "email": raw,
        "domain": get_domain_from_email(raw),
    }


def parse_received_chain(msg: email.message.EmailMessage) -> list[dict]:
    """
    Parse the chain of Received: headers (in chronological order, oldest first).
    Each hop tells us where the email passed through.
    """
    received_headers = msg.get_all("Received") or []
    hops = []
    for header in reversed(received_headers):  # oldest first
        hop = _parse_received_header(header)
        hops.append(hop)
    return hops


def _parse_received_header(raw: str) -> dict:
    """Parse a single Received: header line."""
    hop = {
        "raw": raw[:500],
        "from": "",
        "by": "",
        "ip": "",
        "timestamp": "",
        "tls": False,
    }
    try:
        # Extract 'from' domain
        m = re.search(r'from\s+(\S+)', raw, re.IGNORECASE)
        if m:
            hop["from"] = m.group(1)

        # Extract 'by' server
        m = re.search(r'by\s+(\S+)', raw, re.IGNORECASE)
        if m:
            hop["by"] = m.group(1)

        # Extract IP address
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', raw)
        if ip_match:
            hop["ip"] = ip_match.group(1)

        # Detect TLS/encryption
        if re.search(r'TLS|ESMTPS|STARTTLS|SSL', raw, re.IGNORECASE):
            hop["tls"] = True

        # Extract timestamp (last semicolon-separated value)
        parts = raw.rsplit(";", 1)
        if len(parts) > 1:
            hop["timestamp"] = parts[-1].strip()

    except Exception as e:
        logger.debug(f"Received header parse error: {e}")
    return hop


def parse_authentication_results(msg: email.message.EmailMessage) -> dict:
    """
    Parse Authentication-Results header (added by receiving mail server).
    Contains SPF, DKIM, DMARC verdicts assigned by the receiver.
    """
    results = {
        "raw": "",
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "compauth": "none",
        "header_present": False,
    }
    raw = msg.get("Authentication-Results", "")
    if not raw:
        return results
    results["raw"] = raw
    results["header_present"] = True

    # SPF
    m = re.search(r'spf\s*=\s*(\w+)', raw, re.IGNORECASE)
    if m:
        results["spf"] = m.group(1).lower()

    # DKIM
    m = re.search(r'dkim\s*=\s*(\w+)', raw, re.IGNORECASE)
    if m:
        results["dkim"] = m.group(1).lower()

    # DMARC
    m = re.search(r'dmarc\s*=\s*(\w+)', raw, re.IGNORECASE)
    if m:
        results["dmarc"] = m.group(1).lower()

    # Microsoft CompAuth (composite authentication)
    m = re.search(r'compauth\s*=\s*(\w+)', raw, re.IGNORECASE)
    if m:
        results["compauth"] = m.group(1).lower()

    return results


def parse_received_spf(msg: email.message.EmailMessage) -> dict:
    """Parse the Received-SPF header (added by receiver's MTA)."""
    results = {
        "raw": "",
        "result": "none",
        "client_ip": "",
        "envelope_from": "",
    }
    raw = msg.get("Received-SPF", "")
    if not raw:
        return results
    results["raw"] = raw

    # SPF result is the first word
    m = re.match(r'(\w+)', raw.strip())
    if m:
        results["result"] = m.group(1).lower()

    # Client IP
    m = re.search(r'client-ip\s*=\s*(\S+)', raw, re.IGNORECASE)
    if m:
        results["client_ip"] = m.group(1).strip(";")

    # Envelope from
    m = re.search(r'envelope-from\s*=\s*(\S+)', raw, re.IGNORECASE)
    if m:
        results["envelope_from"] = m.group(1).strip(";")

    return results


def parse_dkim_signature(msg: email.message.EmailMessage) -> dict:
    """Parse DKIM-Signature header."""
    results = {
        "present": False,
        "version": "",
        "algorithm": "",
        "domain": "",
        "selector": "",
        "headers_signed": [],
        "body_hash": "",
        "signature": "",
        "raw": "",
    }
    raw = msg.get("DKIM-Signature", "")
    if not raw:
        return results
    results["present"] = True
    results["raw"] = raw[:500]

    # Parse tags (key=value; pairs)
    tags = dict(re.findall(r'(\w+)\s*=\s*([^;]+)', raw))

    results["version"] = tags.get("v", "").strip()
    results["algorithm"] = tags.get("a", "").strip()
    results["domain"] = tags.get("d", "").strip()
    results["selector"] = tags.get("s", "").strip()
    results["body_hash"] = tags.get("bh", "").strip()[:32] + "..." if tags.get("bh") else ""
    results["signature"] = tags.get("b", "").strip()[:32] + "..." if tags.get("b") else ""

    h_field = tags.get("h", "")
    results["headers_signed"] = [h.strip() for h in h_field.split(":") if h.strip()]

    return results


def detect_header_spoofing(msg: email.message.EmailMessage) -> dict:
    """
    Detect common email spoofing indicators from headers.
    Returns findings with risk scores.
    """
    findings = []
    risk_delta = 0

    from_data = parse_from_header(msg)
    reply_to = parse_reply_to(msg)
    envelope = parse_envelope_sender(msg)
    auth = parse_authentication_results(msg)

    from_domain = from_data.get("domain", "")
    reply_domain = reply_to.get("domain", "")
    envelope_domain = envelope.get("domain", "")

    # ── Check 1: Reply-To domain differs from From domain ─────────────────
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({
            "type": "reply_to_mismatch",
            "severity": "HIGH",
            "description": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}). "
                           "Replies will go to a different domain than the sender — classic phishing tactic.",
            "detail": f"From: {from_domain} | Reply-To: {reply_domain}",
        })
        risk_delta += 25

    # ── Check 2: Envelope sender domain differs from From domain ──────────
    if envelope_domain and from_domain and envelope_domain != from_domain:
        findings.append({
            "type": "envelope_from_mismatch",
            "severity": "HIGH",
            "description": f"Envelope sender ({envelope_domain}) differs from From header ({from_domain}). "
                           "The actual sending server claims to be from a different domain.",
            "detail": f"MAIL FROM domain: {envelope_domain} | Header From domain: {from_domain}",
        })
        risk_delta += 20

    # ── Check 3: SPF failure ───────────────────────────────────────────────
    spf_result = auth.get("spf", "none")
    if spf_result in ("fail", "softfail"):
        findings.append({
            "type": "spf_failure",
            "severity": "HIGH" if spf_result == "fail" else "MEDIUM",
            "description": f"SPF check {spf_result}. The sending server is NOT authorized to send "
                           f"email on behalf of {from_domain}.",
            "detail": f"SPF result: {spf_result}",
        })
        risk_delta += 30 if spf_result == "fail" else 15

    # ── Check 4: DKIM failure ─────────────────────────────────────────────
    dkim_result = auth.get("dkim", "none")
    if dkim_result in ("fail", "none", "temperror", "permerror"):
        severity = "HIGH" if dkim_result == "fail" else "MEDIUM"
        findings.append({
            "type": "dkim_failure",
            "severity": severity,
            "description": f"DKIM check {dkim_result}. Email signature cannot be verified — "
                           "message may have been tampered with in transit.",
            "detail": f"DKIM result: {dkim_result}",
        })
        risk_delta += 25 if dkim_result == "fail" else 10

    # ── Check 5: DMARC failure ────────────────────────────────────────────
    dmarc_result = auth.get("dmarc", "none")
    if dmarc_result in ("fail",):
        findings.append({
            "type": "dmarc_failure",
            "severity": "HIGH",
            "description": f"DMARC check failed for {from_domain}. "
                           "The domain owner's policy rejects this email.",
            "detail": f"DMARC result: {dmarc_result}",
        })
        risk_delta += 30

    # ── Check 6: Display name impersonation ───────────────────────────────
    display_name = from_data.get("display_name", "").lower()
    from_email = from_data.get("email", "").lower()
    impersonation_targets = [
        "sbi", "hdfc", "icici", "axis bank", "bank of india", "state bank",
        "income tax", "income-tax", "uidai", "aadhaar", "trai", "sebi",
        "rbi", "reserve bank", "cbi", "police", "cybercell", "amazon",
        "flipkart", "google", "microsoft", "apple", "paypal", "paytm",
        "phonepe", "gpay", "irctc", "epfo", "pf", "provident fund",
        "nsdl", "cbdt", "gst", "customs", "enforcement directorate",
        "ed office", "cbi office", "court", "judiciary",
    ]
    for target in impersonation_targets:
        if target in display_name and target not in from_email:
            findings.append({
                "type": "display_name_impersonation",
                "severity": "HIGH",
                "description": f"Display name '{from_data.get('display_name')}' appears to impersonate "
                               f"'{target}' but the email address domain is '{from_domain}'. "
                               "This is a classic phishing / impersonation technique.",
                "detail": f"Display: {from_data.get('display_name')} | Email: {from_email}",
            })
            risk_delta += 35
            break

    return {
        "findings": findings,
        "risk_delta": risk_delta,
        "from": from_data,
        "reply_to": reply_to,
        "envelope": envelope,
        "auth_results": auth,
    }


def get_message_metadata(msg: email.message.EmailMessage) -> dict:
    """Extract common metadata fields from email."""
    return {
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "x_spam_status": msg.get("X-Spam-Status", ""),
        "x_spam_score": msg.get("X-Spam-Score", ""),
        "content_type": msg.get("Content-Type", ""),
        "mime_version": msg.get("MIME-Version", ""),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "precedence": msg.get("Precedence", ""),
    }
