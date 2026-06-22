# modules/email_analyzer/spf_checker.py
# SPF (Sender Policy Framework) analysis from email headers.
# Parses Authentication-Results and Received-SPF headers.
# Does not require live DNS — works from headers embedded in the email.

import re
import logging
import email.message
from modules.email_analyzer.email_headers import (
    parse_received_spf,
    parse_authentication_results,
    parse_from_header,
    parse_envelope_sender,
)

logger = logging.getLogger(__name__)

SPF_RESULT_SCORES = {
    "pass":      {"score": 0,  "label": "Pass",      "color": "green",  "safe": True},
    "neutral":   {"score": 5,  "label": "Neutral",   "color": "gray",   "safe": True},
    "softfail":  {"score": 20, "label": "SoftFail",  "color": "orange", "safe": False},
    "fail":      {"score": 40, "label": "Fail",      "color": "red",    "safe": False},
    "none":      {"score": 10, "label": "None",      "color": "gray",   "safe": True},
    "temperror": {"score": 10, "label": "TempError", "color": "orange", "safe": True},
    "permerror": {"score": 15, "label": "PermError", "color": "orange", "safe": False},
}


def analyze_spf(msg: email.message.EmailMessage) -> dict:
    """
    Analyze SPF from email headers.
    Returns comprehensive SPF analysis dict.
    """
    # Try Authentication-Results first (most reliable, added by receiver)
    auth = parse_authentication_results(msg)
    spf_from_auth = auth.get("spf", "none")

    # Try Received-SPF header (added by receiver's MTA)
    received_spf = parse_received_spf(msg)
    spf_from_received = received_spf.get("result", "none")

    # Prefer Authentication-Results, fall back to Received-SPF
    final_result = (
        spf_from_auth if spf_from_auth != "none"
        else spf_from_received
    )

    # Normalize
    final_result = final_result.lower().strip()
    if final_result not in SPF_RESULT_SCORES:
        final_result = "none"

    score_info = SPF_RESULT_SCORES[final_result]

    from_data = parse_from_header(msg)
    envelope = parse_envelope_sender(msg)
    from_domain = from_data.get("domain", "unknown")

    findings = []
    risk_delta = score_info["score"]

    if final_result == "fail":
        findings.append(
            f"SPF FAIL: Sending server is NOT authorized to send email for '{from_domain}'. "
            "This is a strong indicator of email spoofing."
        )
    elif final_result == "softfail":
        findings.append(
            f"SPF SOFTFAIL: Sending server is weakly unauthorized for '{from_domain}'. "
            "The domain owner suspects but doesn't enforce rejection."
        )
    elif final_result == "none":
        findings.append(
            f"SPF NONE: Domain '{from_domain}' has no SPF record or SPF was not checked. "
            "This means the sending server cannot be verified against domain policy."
        )
    elif final_result == "pass":
        findings.append(
            f"SPF PASS: Sending server is authorized to send email for '{from_domain}'."
        )

    # Check for domain alignment
    envelope_domain = envelope.get("domain", "")
    if envelope_domain and from_domain and envelope_domain != from_domain:
        findings.append(
            f"SPF ALIGNMENT ISSUE: Envelope sender domain '{envelope_domain}' differs from "
            f"From header domain '{from_domain}'. SPF pass on envelope does not protect From header."
        )
        risk_delta += 10

    return {
        "result": final_result,
        "label": score_info["label"],
        "color": score_info["color"],
        "is_safe": score_info["safe"],
        "risk_delta": risk_delta,
        "findings": findings,
        "from_domain": from_domain,
        "envelope_domain": envelope_domain,
        "client_ip": received_spf.get("client_ip", ""),
        "source": "Authentication-Results" if auth.get("header_present") else "Received-SPF",
        "raw_auth_results": auth.get("raw", ""),
        "raw_received_spf": received_spf.get("raw", ""),
        "recommendation": _get_spf_recommendation(final_result),
    }


def _get_spf_recommendation(result: str) -> str:
    recs = {
        "pass":      "SPF check passed. Sending server is authorized.",
        "neutral":   "SPF returned neutral — domain owner takes no position. Treat with caution.",
        "softfail":  "SPF softfail — likely unauthorized sender. Verify sender identity through other means.",
        "fail":      "SPF FAIL — this email is NOT authorized by the domain owner. High phishing risk.",
        "none":      "No SPF record found. Cannot verify if sender is authorized.",
        "temperror": "Temporary DNS error during SPF check. Try verifying later.",
        "permerror": "Permanent SPF error — possibly misconfigured SPF record. Treat with caution.",
    }
    return recs.get(result, "Unknown SPF result.")
