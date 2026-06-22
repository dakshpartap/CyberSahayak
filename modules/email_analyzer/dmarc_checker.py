# modules/email_analyzer/dmarc_checker.py
# DMARC (Domain-based Message Authentication, Reporting and Conformance) analysis.
# Analyzes DMARC results from Authentication-Results header.

import re
import logging
import email.message
from modules.email_analyzer.email_headers import (
    parse_authentication_results,
    parse_from_header,
)

logger = logging.getLogger(__name__)

DMARC_RESULT_SCORES = {
    "pass":       {"score": 0,  "label": "Pass",      "color": "green",  "safe": True},
    "fail":       {"score": 40, "label": "Fail",       "color": "red",    "safe": False},
    "none":       {"score": 10, "label": "None",       "color": "gray",   "safe": True},
    "temperror":  {"score": 10, "label": "TempError",  "color": "orange", "safe": True},
    "permerror":  {"score": 15, "label": "PermError",  "color": "orange", "safe": False},
    "bestguess":  {"score": 5,  "label": "BestGuess",  "color": "gray",   "safe": True},
}

# DMARC policy severity
POLICY_RISK = {
    "reject":     {"label": "Reject",     "risk": "LOW"},  # domain strongly protected
    "quarantine": {"label": "Quarantine", "risk": "MEDIUM"},
    "none":       {"label": "None",       "risk": "HIGH"},  # no enforcement
    "unknown":    {"label": "Unknown",    "risk": "HIGH"},
}


def analyze_dmarc(msg: email.message.EmailMessage) -> dict:
    """
    Analyze DMARC from email headers.
    Returns comprehensive DMARC analysis dict.
    """
    auth = parse_authentication_results(msg)
    dmarc_result = auth.get("dmarc", "none").lower().strip()

    if dmarc_result not in DMARC_RESULT_SCORES:
        dmarc_result = "none"

    score_info = DMARC_RESULT_SCORES[dmarc_result]
    from_data = parse_from_header(msg)
    from_domain = from_data.get("domain", "unknown")

    # Try to extract policy from Authentication-Results
    raw_auth = auth.get("raw", "")
    policy = _extract_dmarc_policy(raw_auth)
    disposition = _extract_disposition(raw_auth)

    findings = []
    risk_delta = score_info["score"]

    if dmarc_result == "pass":
        findings.append(
            f"DMARC PASS: Email from '{from_domain}' passed DMARC checks. "
            "Both SPF and/or DKIM align with the From domain."
        )
    elif dmarc_result == "fail":
        findings.append(
            f"DMARC FAIL: Email from '{from_domain}' failed DMARC checks. "
            "Neither SPF nor DKIM align with the From header domain. "
            "This is a strong indicator of email spoofing or phishing."
        )
        if policy in ("reject", "quarantine"):
            findings.append(
                f"Domain policy is '{policy}' — legitimate email from this domain should "
                "have been rejected/quarantined. The fact that it reached you is suspicious."
            )
    elif dmarc_result == "none":
        findings.append(
            f"DMARC NONE: Domain '{from_domain}' has no DMARC record or DMARC was not checked. "
            "Cannot verify sender domain authentication."
        )

    # Policy analysis
    policy_info = POLICY_RISK.get(policy, POLICY_RISK["unknown"])
    if policy_info["risk"] == "HIGH" and dmarc_result in ("fail", "none"):
        risk_delta += 10
        findings.append(
            f"Domain DMARC policy is '{policy}' — no enforcement. "
            "Attackers can easily spoof this domain."
        )

    # Check compauth (Microsoft-specific composite auth)
    compauth = auth.get("compauth", "")
    compauth_reason = _extract_compauth_reason(raw_auth)
    compauth_findings = []
    if compauth and compauth not in ("pass", "none", ""):
        compauth_findings.append(
            f"Microsoft composite authentication: {compauth} "
            f"(reason: {compauth_reason or 'unknown'})"
        )

    return {
        "result": dmarc_result,
        "label": score_info["label"],
        "color": score_info["color"],
        "is_safe": score_info["safe"],
        "risk_delta": risk_delta,
        "findings": findings,
        "compauth_findings": compauth_findings,
        "from_domain": from_domain,
        "policy": policy,
        "policy_label": policy_info["label"],
        "policy_risk": policy_info["risk"],
        "disposition": disposition,
        "header_present": auth.get("header_present", False),
        "recommendation": _get_dmarc_recommendation(dmarc_result, policy),
    }


def _extract_dmarc_policy(raw: str) -> str:
    """Extract DMARC policy from Authentication-Results string."""
    # e.g., "dmarc=fail (p=reject sp=reject ...)"
    m = re.search(r'p\s*=\s*(reject|quarantine|none)', raw, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return "unknown"


def _extract_disposition(raw: str) -> str:
    """Extract disposition (what action the receiver took)."""
    m = re.search(r'action\s*=\s*(\w+)', raw, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return ""


def _extract_compauth_reason(raw: str) -> str:
    """Extract Microsoft compauth reason code."""
    m = re.search(r'reason\s*=\s*([0-9]+)', raw, re.IGNORECASE)
    if m:
        code = m.group(1)
        reasons = {
            "000": "Message passed DMARC",
            "001": "Message passed DMARC implicit",
            "002": "Policy was override, signed by accepted domain",
            "010": "Message failed DMARC",
            "011": "Message failed DMARC, explicitly rejected",
            "012": "DMARC explicit fail, sender passed implicit check",
            "022": "Message failed explicit email authentication",
            "049": "Bulk mail sender, passed implicit checks",
            "100": "Message failed compauth",
            "130": "Message is phishing",
            "131": "Message is high confidence phishing",
            "250": "Message is bulk email",
            "350": "Message quarantined",
            "451": "Message passed SPF",
            "550": "Message rejected",
            "601": "Message spoof",
        }
        return reasons.get(code, f"Code {code}")
    return ""


def _get_dmarc_recommendation(result: str, policy: str) -> str:
    if result == "pass":
        return "DMARC passed. Email authentication is valid."
    if result == "fail":
        return (
            f"DMARC FAILED with policy '{policy}'. "
            "This email may be spoofed or phished. Do not click links or provide information."
        )
    if result == "none":
        return (
            "No DMARC result available. Verify sender through additional means. "
            "Do not rely solely on the From address."
        )
    return "Verify sender identity through other channels."
