# modules/email_analyzer/dkim_checker.py
# DKIM (DomainKeys Identified Mail) analysis from email headers.
# Analyzes DKIM-Signature and Authentication-Results without live DNS.

import re
import base64
import logging
import email.message
from modules.email_analyzer.email_headers import (
    parse_dkim_signature,
    parse_authentication_results,
    parse_from_header,
)

logger = logging.getLogger(__name__)

DKIM_RESULT_SCORES = {
    "pass":       {"score": 0,  "label": "Pass",       "color": "green",  "safe": True},
    "fail":       {"score": 35, "label": "Fail",       "color": "red",    "safe": False},
    "none":       {"score": 10, "label": "None",       "color": "gray",   "safe": True},
    "temperror":  {"score": 10, "label": "TempError",  "color": "orange", "safe": True},
    "permerror":  {"score": 20, "label": "PermError",  "color": "orange", "safe": False},
    "neutral":    {"score": 5,  "label": "Neutral",    "color": "gray",   "safe": True},
    "policy":     {"score": 15, "label": "Policy",     "color": "orange", "safe": False},
}

# DKIM algorithms considered weak
_WEAK_ALGORITHMS = {"rsa-sha1", "rsa-sha0"}
# Minimum acceptable RSA key size in bits
_MIN_RSA_KEY_BITS = 1024


def analyze_dkim(msg: email.message.EmailMessage) -> dict:
    """
    Analyze DKIM from email headers.
    Returns comprehensive DKIM analysis dict.
    """
    auth = parse_authentication_results(msg)
    dkim_result = auth.get("dkim", "none").lower().strip()

    sig = parse_dkim_signature(msg)
    from_data = parse_from_header(msg)
    from_domain = from_data.get("domain", "")

    if dkim_result not in DKIM_RESULT_SCORES:
        dkim_result = "none" if not sig.get("present") else "none"

    score_info = DKIM_RESULT_SCORES.get(dkim_result, DKIM_RESULT_SCORES["none"])
    findings = []
    risk_delta = score_info["score"]
    warnings = []

    # ── Signature presence ─────────────────────────────────────────────────
    if not sig.get("present"):
        findings.append(
            "No DKIM-Signature header found. This email has not been digitally signed."
        )
        risk_delta += 5

    # ── Result analysis ────────────────────────────────────────────────────
    if dkim_result == "pass":
        findings.append(
            f"DKIM PASS: Digital signature verified. Email integrity is confirmed for "
            f"domain '{sig.get('domain', from_domain)}'."
        )
    elif dkim_result == "fail":
        findings.append(
            "DKIM FAIL: Signature verification failed. The email body or headers were "
            "modified after signing, or the signature is forged."
        )
    elif dkim_result == "none":
        findings.append(
            "DKIM NONE: No valid DKIM signature could be verified."
        )

    # ── Algorithm check ────────────────────────────────────────────────────
    algorithm = sig.get("algorithm", "").lower()
    if algorithm in _WEAK_ALGORITHMS:
        warnings.append(
            f"Weak DKIM algorithm '{algorithm}' detected. SHA-1 based signatures are "
            "cryptographically weak and should not be trusted."
        )
        risk_delta += 10

    # ── Domain alignment check ─────────────────────────────────────────────
    sig_domain = sig.get("domain", "").lower()
    if sig_domain and from_domain and sig_domain != from_domain:
        # Check for organizational domain alignment
        from_org = _get_org_domain(from_domain)
        sig_org = _get_org_domain(sig_domain)
        if from_org != sig_org:
            findings.append(
                f"DKIM ALIGNMENT FAIL: DKIM signed domain ('{sig_domain}') does not match "
                f"From header domain ('{from_domain}'). This is a spoofing indicator."
            )
            risk_delta += 20
        else:
            findings.append(
                f"DKIM organizational alignment OK: Signed domain '{sig_domain}' shares "
                f"organization with '{from_domain}'."
            )

    # ── Critical headers check ─────────────────────────────────────────────
    headers_signed = [h.lower() for h in sig.get("headers_signed", [])]
    critical_headers = {"from", "subject", "to", "date"}
    missing_critical = critical_headers - set(headers_signed)
    if missing_critical and sig.get("present"):
        warnings.append(
            f"DKIM signature does not cover critical headers: {', '.join(sorted(missing_critical))}. "
            "An attacker could modify these without invalidating the signature."
        )
        risk_delta += 10

    return {
        "result": dkim_result,
        "label": score_info["label"],
        "color": score_info["color"],
        "is_safe": score_info["safe"],
        "risk_delta": risk_delta,
        "findings": findings,
        "warnings": warnings,
        "signature_present": sig.get("present", False),
        "signing_domain": sig_domain,
        "from_domain": from_domain,
        "algorithm": sig.get("algorithm", ""),
        "selector": sig.get("selector", ""),
        "headers_signed": sig.get("headers_signed", []),
        "recommendation": _get_dkim_recommendation(dkim_result),
    }


def _get_org_domain(domain: str) -> str:
    """Get organizational domain (e.g., mail.example.com -> example.com)."""
    if not domain:
        return ""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _get_dkim_recommendation(result: str) -> str:
    recs = {
        "pass":      "DKIM signature verified. Message integrity confirmed.",
        "fail":      "DKIM FAIL — message was modified after signing or signature is forged. "
                     "Do not trust this email.",
        "none":      "No DKIM signature present. Cannot verify message integrity.",
        "temperror": "Temporary DKIM verification error. May be a transient DNS issue.",
        "permerror": "Permanent DKIM error — likely misconfigured signing policy.",
        "neutral":   "DKIM returned neutral result. Verify sender through other channels.",
        "policy":    "DKIM policy rejection. Sender domain has configured strict policies.",
    }
    return recs.get(result, "Unknown DKIM result.")
