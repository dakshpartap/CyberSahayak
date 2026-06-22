# modules/email_analyzer/email_verification.py
# Verify sender domains, detect fake domains, check domain age indicators.
# Works without live DNS — uses structural heuristics and known lists.

import re
import socket
import logging
import email.message
from modules.email_analyzer.email_parser import get_domain_from_email
from modules.email_analyzer.email_headers import parse_from_header, parse_reply_to

logger = logging.getLogger(__name__)

# ── Known legitimate domains for major Indian services ────────────────────
LEGITIMATE_DOMAINS = {
    # Indian Government
    "gov.in", "nic.in", "uidai.gov.in", "incometax.gov.in", "gst.gov.in",
    "cbdt.gov.in", "sebi.gov.in", "rbi.org.in", "mha.gov.in", "cert-in.org.in",
    "npci.org.in", "cybercrime.gov.in", "trai.gov.in", "irctc.co.in",
    "epfindia.gov.in", "nsdl.co.in", "cbi.gov.in",
    # Major banks
    "sbi.co.in", "onlinesbi.sbi", "sbionline.com",
    "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "kotakbank.com", "yesbank.in",
    "pnbindia.in", "bankofbaroda.in", "canarabank.in",
    "unionbankofindia.co.in", "indianbank.in",
    # Payment platforms
    "paytm.com", "phonepe.com", "googlepay.com",
    "npci.org.in", "bhimupi.org.in",
    # E-commerce
    "amazon.in", "flipkart.com", "myntra.com", "snapdeal.com",
    # Tech
    "google.com", "microsoft.com", "apple.com", "outlook.com",
    "yahoo.com", "gmail.com", "protonmail.com",
}

# ── Known phishing domain patterns ────────────────────────────────────────
PHISHING_PATTERNS = [
    # Bank name in non-official domain
    (r"sbi[-.]online", "SBI phishing pattern"),
    (r"sbi[-.]net\b", "SBI phishing pattern"),
    (r"sbionline\.(com|net|org|in)(?!\.in)", "Fake SBI domain"),
    (r"hdfc[-.]bank(?!\.com)", "HDFC phishing pattern"),
    (r"icici[-.]bank(?!\.com)", "ICICI phishing pattern"),
    (r"axis[-.]bank(?!\.com)", "Axis phishing pattern"),
    # Government impersonation
    (r"income[-.]?tax(?!\.gov\.in)", "Fake Income Tax domain"),
    (r"uidai(?!\.gov\.in)", "Fake AADHAAR domain"),
    (r"trai(?!\.gov\.in)", "Fake TRAI domain"),
    (r"sebi(?!\.gov\.in)", "Fake SEBI domain"),
    # Payment platform impersonation
    (r"paytm(?!\.com)", "Fake PayTM domain"),
    (r"phonepe(?!\.com)", "Fake PhonePe domain"),
    # Common phishing tricks
    (r"secure[-.]?update", "Fake security update"),
    (r"verify[-.]?account", "Fake account verification"),
    (r"kyc[-.]?update", "Fake KYC update"),
    (r"account[-.]?suspended", "Fake suspension notice"),
    (r"[0-9]{4,}\.(?:com|in|net|org)", "IP-like numeric domain"),
    # Homograph patterns
    (r"(?:g00gle|micr0soft|amaz0n|paypa1|b4nk)", "Homograph attack domain"),
]

# ── Suspicious TLDs often used in phishing ────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
    ".xyz", ".top", ".club", ".online", ".site", ".website",
    ".click", ".link", ".download", ".win", ".faith", ".stream",
    ".bid", ".trade", ".party",
}

# ── Disposable email domain patterns ──────────────────────────────────────
DISPOSABLE_PATTERNS = [
    "mailinator", "guerrillamail", "tempmail", "throwam", "maildrop",
    "yopmail", "sharklasers", "guerrillamailblock", "trashmail",
    "10minutemail", "fakeinbox", "dispostable", "spamgourmet",
]


def verify_sender_domain(msg: email.message.EmailMessage) -> dict:
    """
    Comprehensive sender domain verification.
    Returns dict with verification results and risk score.
    """
    from_data = parse_from_header(msg)
    from_domain = from_data.get("domain", "")
    from_email = from_data.get("email", "")

    findings = []
    risk_delta = 0

    if not from_domain:
        findings.append({
            "type": "missing_domain",
            "severity": "HIGH",
            "description": "No sender domain found in From header. Highly suspicious.",
        })
        return {
            "domain": "",
            "email": from_email,
            "findings": findings,
            "risk_delta": 40,
            "is_legitimate": False,
            "is_phishing_domain": True,
            "is_disposable": False,
            "has_suspicious_tld": False,
            "domain_type": "missing",
            "mx_resolvable": False,
        }

    is_legitimate = _check_legitimate(from_domain)
    phishing_match = _check_phishing_patterns(from_domain)
    is_disposable = _check_disposable(from_domain)
    has_suspicious_tld = _check_suspicious_tld(from_domain)
    mx_resolvable = _check_mx_resolvable(from_domain)
    domain_type = _classify_domain(from_domain)

    # Score
    if is_legitimate:
        findings.append({
            "type": "legitimate_domain",
            "severity": "INFO",
            "description": f"Domain '{from_domain}' is a known legitimate service domain.",
        })
    else:
        if phishing_match:
            match_pattern, match_reason = phishing_match
            findings.append({
                "type": "phishing_domain_pattern",
                "severity": "CRITICAL",
                "description": f"Domain '{from_domain}' matches phishing pattern: {match_reason}",
                "detail": f"Pattern: {match_pattern}",
            })
            risk_delta += 50

        if is_disposable:
            findings.append({
                "type": "disposable_domain",
                "severity": "HIGH",
                "description": f"Domain '{from_domain}' appears to be a disposable/temporary email service. "
                               "Legitimate organizations do not use disposable email domains.",
            })
            risk_delta += 30

        if has_suspicious_tld:
            tld = "." + from_domain.rsplit(".", 1)[-1]
            findings.append({
                "type": "suspicious_tld",
                "severity": "MEDIUM",
                "description": f"Domain uses suspicious TLD '{tld}' commonly associated with phishing sites.",
            })
            risk_delta += 20

        if not mx_resolvable:
            findings.append({
                "type": "domain_unresolvable",
                "severity": "HIGH",
                "description": f"Domain '{from_domain}' could not be resolved. It may not exist or be newly registered.",
            })
            risk_delta += 25

    # Check display name vs domain mismatch (impersonation)
    display_name = from_data.get("display_name", "").lower()
    if display_name:
        impersonation = _check_display_name_impersonation(display_name, from_domain)
        if impersonation:
            findings.append({
                "type": "display_name_impersonation",
                "severity": "CRITICAL",
                "description": impersonation,
            })
            risk_delta += 40

    return {
        "domain": from_domain,
        "email": from_email,
        "display_name": from_data.get("display_name", ""),
        "findings": findings,
        "risk_delta": min(risk_delta, 100),
        "is_legitimate": is_legitimate,
        "is_phishing_domain": bool(phishing_match),
        "is_disposable": is_disposable,
        "has_suspicious_tld": has_suspicious_tld,
        "mx_resolvable": mx_resolvable,
        "domain_type": domain_type,
    }


def _check_legitimate(domain: str) -> bool:
    """Check if domain is in the known legitimate list."""
    domain = domain.lower()
    # Exact match
    if domain in LEGITIMATE_DOMAINS:
        return True
    # Suffix match (e.g., "mail.sbi.co.in" matches "sbi.co.in")
    for legit in LEGITIMATE_DOMAINS:
        if domain.endswith("." + legit):
            return True
    return False


def _check_phishing_patterns(domain: str) -> tuple:
    """Returns (pattern, reason) if domain matches a phishing pattern, else None."""
    domain = domain.lower()
    for pattern, reason in PHISHING_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            return (pattern, reason)
    return None


def _check_disposable(domain: str) -> bool:
    """Check if domain is a disposable email service."""
    domain = domain.lower()
    for d in DISPOSABLE_PATTERNS:
        if d in domain:
            return True
    return False


def _check_suspicious_tld(domain: str) -> bool:
    """Check if domain uses a suspicious TLD."""
    parts = domain.rstrip(".").split(".")
    if not parts:
        return False
    tld = "." + parts[-1].lower()
    return tld in SUSPICIOUS_TLDS


def _check_mx_resolvable(domain: str) -> bool:
    """
    Check if domain has resolvable A record (lightweight check).
    Note: This checks A record, not MX — available via socket.
    """
    try:
        socket.getaddrinfo(domain, None, timeout=2)
        return True
    except (socket.gaierror, OSError):
        return False
    except Exception:
        return False


def _classify_domain(domain: str) -> str:
    """Classify domain type for display."""
    domain = domain.lower()
    if domain.endswith(".gov.in") or domain.endswith(".nic.in"):
        return "Indian Government"
    if domain.endswith(".edu.in") or domain.endswith(".ac.in"):
        return "Indian Education"
    if domain.endswith(".co.in") or domain.endswith(".in"):
        return "Indian Commercial"
    if domain in ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com"):
        return "Free Email Provider"
    return "Commercial"


def _check_display_name_impersonation(display_name: str, from_domain: str) -> str:
    """Check if display name claims to be org that doesn't match the domain."""
    impersonation_map = {
        "sbi": "sbi.co.in",
        "state bank": "sbi.co.in",
        "hdfc": "hdfcbank.com",
        "icici": "icicibank.com",
        "axis bank": "axisbank.com",
        "income tax": "incometax.gov.in",
        "uidai": "uidai.gov.in",
        "aadhaar": "uidai.gov.in",
        "trai": "trai.gov.in",
        "sebi": "sebi.gov.in",
        "rbi": "rbi.org.in",
        "reserve bank": "rbi.org.in",
        "cbi": "cbi.gov.in",
        "amazon": "amazon.in",
        "paytm": "paytm.com",
        "phonepe": "phonepe.com",
        "flipkart": "flipkart.com",
        "google": "google.com",
        "microsoft": "microsoft.com",
    }
    from_domain = from_domain.lower()
    for org, expected_domain in impersonation_map.items():
        if org in display_name:
            if not (from_domain == expected_domain or from_domain.endswith("." + expected_domain)):
                return (
                    f"Display name claims to be '{org}' but email is from '{from_domain}', "
                    f"not the official '{expected_domain}'. This is impersonation / phishing."
                )
    return ""
