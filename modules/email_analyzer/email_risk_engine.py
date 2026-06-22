# modules/email_analyzer/email_risk_engine.py
# Orchestrates SPF/DKIM/DMARC/phishing/base64/verification checks into a
# single risk score and verdict. Integrates with core.risk_engine where possible.

import logging
import email.message
from datetime import datetime, timezone
from modules.url_analyzer.ml_model import predict_url
from modules.email_analyzer.spf_checker import analyze_spf
from modules.email_analyzer.dkim_checker import analyze_dkim
from modules.email_analyzer.dmarc_checker import analyze_dmarc
from modules.email_analyzer.email_verification import verify_sender_domain
from modules.email_analyzer.email_phishing_detector import detect_phishing
from modules.email_analyzer.email_headers import (
    detect_header_spoofing,
    get_message_metadata,
    parse_from_header,
)
from modules.email_analyzer.base64_detector import scan_text_for_base64
from modules.email_analyzer.email_parser import (
    extract_text_body,
    extract_html_body,
    get_attachments,
    get_all_urls,
)

logger = logging.getLogger(__name__)

# ── Verdict thresholds ──────────────────────────────────────────────────────
VERDICT_THRESHOLDS = [
    (75, "PHISHING / HIGH RISK", "🔴"),
    (50, "PHISHING", "🟠"),
    (25, "SUSPICIOUS", "🟡"),
    (0,  "SAFE", "🟢"),
]

# Component weights for final aggregation
COMPONENT_WEIGHTS = {
    "spf": 0.15,
    "dkim": 0.15,
    "dmarc": 0.15,
    "domain_verification": 0.20,
    "header_spoofing": 0.15,
    "phishing_content": 0.15,
    "base64": 0.05,
}


def analyze_email(
    msg: email.message.EmailMessage,
    include_base64: bool = True,
) -> dict:
    """
    Full email analysis pipeline. Runs all checks and aggregates into
    a final risk score + verdict.

    Never raises — every sub-check is wrapped so one failure doesn't
    crash the whole pipeline.

    Returns a comprehensive dict ready for display and reporting.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    component_results = {}
    component_scores = {}
    all_findings = []
    errors = []

    # ── SPF ──────────────────────────────────────────────────────────────
    try:
        spf_result = analyze_spf(msg)
        component_results["spf"] = spf_result
        component_scores["spf"] = spf_result.get("risk_delta", 0)
        all_findings.extend(
            _wrap_findings(spf_result.get("findings", []), "SPF")
        )
    except Exception as e:
        logger.error(f"SPF check failed: {e}")
        errors.append(f"SPF check error: {e}")
        component_results["spf"] = _error_component("spf")
        component_scores["spf"] = 0

    # ── DKIM ─────────────────────────────────────────────────────────────
    try:
        dkim_result = analyze_dkim(msg)
        component_results["dkim"] = dkim_result
        component_scores["dkim"] = dkim_result.get("risk_delta", 0)
        all_findings.extend(
            _wrap_findings(dkim_result.get("findings", []), "DKIM")
        )
        all_findings.extend(
            _wrap_findings(dkim_result.get("warnings", []), "DKIM Warning")
        )
    except Exception as e:
        logger.error(f"DKIM check failed: {e}")
        errors.append(f"DKIM check error: {e}")
        component_results["dkim"] = _error_component("dkim")
        component_scores["dkim"] = 0

    # ── DMARC ────────────────────────────────────────────────────────────
    try:
        dmarc_result = analyze_dmarc(msg)
        component_results["dmarc"] = dmarc_result
        component_scores["dmarc"] = dmarc_result.get("risk_delta", 0)
        all_findings.extend(
            _wrap_findings(dmarc_result.get("findings", []), "DMARC")
        )
    except Exception as e:
        logger.error(f"DMARC check failed: {e}")
        errors.append(f"DMARC check error: {e}")
        component_results["dmarc"] = _error_component("dmarc")
        component_scores["dmarc"] = 0

    # ── Domain / Sender Verification ────────────────────────────────────
    try:
        domain_result = verify_sender_domain(msg)
        component_results["domain_verification"] = domain_result
        component_scores["domain_verification"] = domain_result.get("risk_delta", 0)
        for f in domain_result.get("findings", []):
            all_findings.append({
                "category": "Domain Verification",
                "severity": f.get("severity", "MEDIUM"),
                "description": f.get("description", ""),
            })
    except Exception as e:
        logger.error(f"Domain verification failed: {e}")
        errors.append(f"Domain verification error: {e}")
        component_results["domain_verification"] = _error_component("domain_verification")
        component_scores["domain_verification"] = 0

    # ── Header Spoofing Detection ────────────────────────────────────────
    try:
        spoof_result = detect_header_spoofing(msg)
        component_results["header_spoofing"] = spoof_result
        component_scores["header_spoofing"] = spoof_result.get("risk_delta", 0)
        for f in spoof_result.get("findings", []):
            all_findings.append({
                "category": "Header Spoofing",
                "severity": f.get("severity", "MEDIUM"),
                "description": f.get("description", ""),
            })
    except Exception as e:
        logger.error(f"Header spoofing check failed: {e}")
        errors.append(f"Header spoofing error: {e}")
        component_results["header_spoofing"] = _error_component("header_spoofing")
        component_scores["header_spoofing"] = 0

    # ── Phishing Content Detection ───────────────────────────────────────
    try:
        phishing_result = detect_phishing(msg)
        component_results["phishing_content"] = phishing_result
        component_scores["phishing_content"] = phishing_result.get("risk_delta", 0)
        for f in phishing_result.get("findings", []):
            all_findings.append({
                "category": f.get("category", "Phishing"),
                "severity": _score_to_severity(f.get("score", 10)),
                "description": f.get("description", ""),
            })
    except Exception as e:
        logger.error(f"Phishing detection failed: {e}")
        errors.append(f"Phishing detection error: {e}")
        component_results["phishing_content"] = _error_component("phishing_content")
        component_scores["phishing_content"] = 0

    # ── Base64 Analysis ──────────────────────────────────────────────────
    base64_result = {"risk_delta": 0, "findings": [], "base64_detected": False}
    if include_base64:
        try:
            text_body = extract_text_body(msg)
            html_body = extract_html_body(msg)
            combined = text_body + "\n" + html_body
            base64_result = scan_text_for_base64(combined)
            component_results["base64"] = base64_result
            component_scores["base64"] = base64_result.get("risk_delta", 0)
            for f in base64_result.get("findings", []):
                all_findings.append({
                    "category": "Base64 Hidden Content",
                    "severity": f.get("severity", "MEDIUM"),
                    "description": f.get("description", ""),
                })
        except Exception as e:
            logger.error(f"Base64 scan failed: {e}")
            errors.append(f"Base64 scan error: {e}")
            component_results["base64"] = _error_component("base64")
            component_scores["base64"] = 0
    else:
        component_results["base64"] = base64_result
        component_scores["base64"] = 0

    # ── Aggregate Final Score ────────────────────────────────────────────
    final_score = _compute_weighted_score(component_scores)
    verdict, verdict_emoji = _get_verdict(final_score)

    # ── Critical overrides ───────────────────────────────────────────────
    critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    if critical_count >= 2:
        final_score = max(final_score, 80)
        if any(
            f.get("category") == "URL Analysis"
            and f.get("severity") == "CRITICAL"
            for f in all_findings
        ):
            final_score = max(final_score, 90)
        verdict, verdict_emoji = _get_verdict(final_score)

    # ── Metadata ─────────────────────────────────────────────────────────
    try:
        metadata = get_message_metadata(msg)
    except Exception:
        metadata = {}

    try:
        from_data = parse_from_header(msg)
    except Exception:
        from_data = {}

    url_analysis_results = []
    try:
        urls = get_all_urls(msg)
        for url in urls:
            try:
                url_result = predict_url(url)
                url_analysis_results.append({
                    "url": url,
                    "risk": url_result.get("final_risk", 0),
                    "verdict": url_result.get("verdict", "Unknown")
                })

                if url_result.get("final_risk", 0) >= 90:
                    final_score += 50
                    all_findings.append({
                        "category": "URL Analysis",
                        "severity": "CRITICAL",
                        "description": (
                            f"Embedded URL confirmed phishing: {url}"
                        ),
                    })

                elif url_result.get("final_risk", 0) >= 75:
                    final_score += 35
                    all_findings.append({
                        "category": "URL Analysis",
                        "severity": "HIGH",
                        "description": (
                            f"Embedded URL highly suspicious: {url}"
                        ),
                    })
            except Exception as e:
                logger.error(f"Email URL analysis failed: {e}")
        
    except Exception:
        urls = []

    try:
        attachments = get_attachments(msg)
    except Exception:
        attachments = []

    recommendations = _generate_recommendations(final_score, component_results, all_findings)
    return {
        "timestamp": timestamp,
        "final_score": final_score,
        "verdict": verdict,
        "verdict_emoji": verdict_emoji,
        "verdict_full": f"{verdict_emoji} {verdict}",
        "component_scores": component_scores,
        "component_results": component_results,
        "all_findings": sorted(
            all_findings,
            key=lambda f: _severity_rank(f.get("severity", "LOW")),
            reverse=True,
        ),
        "critical_count": critical_count,
        "high_count": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
        "medium_count": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
        "total_findings": len(all_findings),
        "from": from_data,
        "metadata": metadata,
        "url_analysis": url_analysis_results,
        "urls": urls,
        "url_count": len(urls),
        "attachments": attachments,
        "attachment_count": len(attachments),
        "recommendations": recommendations,
        "errors": errors,
        "spf_label": component_results.get("spf", {}).get("label", "Unknown"),
        "dkim_label": component_results.get("dkim", {}).get("label", "Unknown"),
        "dmarc_label": component_results.get("dmarc", {}).get("label", "Unknown"),
    }


def _compute_weighted_score(component_scores: dict) -> int:
    """Weighted aggregation of component risk deltas into a 0-100 score."""
    total = 0.0
    for component, weight in COMPONENT_WEIGHTS.items():
        raw_score = component_scores.get(component, 0)
        # Each component's risk_delta is already roughly 0-100 scale
        normalized = min(raw_score, 100)
        total += normalized * weight

    # Boost for compounding signals: if 3+ components show risk, increase severity
    risky_components = sum(1 for v in component_scores.values() if v >= 20)
    if risky_components >= 4:
        total = min(total * 1.25, 100)
    elif risky_components >= 3:
        total = min(total * 1.15, 100)

    return int(round(min(max(total, 0), 100)))


def _get_verdict(score: int) -> tuple[str, str]:
    for threshold, verdict, emoji in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict, emoji
    return "SAFE", "🟢"


def _score_to_severity(score: int) -> str:
    if score >= 30:
        return "CRITICAL"
    if score >= 18:
        return "HIGH"
    if score >= 8:
        return "MEDIUM"
    return "LOW"


def _severity_rank(severity: str) -> int:
    ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return ranks.get(severity, 0)


def _wrap_findings(findings: list, category: str) -> list[dict]:
    """Convert plain string findings into structured dicts."""
    wrapped = []
    for f in findings:
        if isinstance(f, dict):
            wrapped.append(f)
        else:
            severity = "HIGH" if any(
                w in str(f).upper() for w in ("FAIL", "CRITICAL", "PHISHING", "SPOOF")
            ) else "MEDIUM"
            wrapped.append({
                "category": category,
                "severity": severity,
                "description": str(f),
            })
    return wrapped


def _error_component(name: str) -> dict:
    return {
        "result": "error",
        "label": "Check Failed",
        "color": "gray",
        "is_safe": True,
        "risk_delta": 0,
        "findings": [],
        "error": True,
    }


def _generate_recommendations(score: int, components: dict, findings: list) -> list[str]:
    """Generate actionable recommendations based on analysis results."""
    recs = []

    if score >= 75:
        recs.append("🚨 DO NOT click any links or download any attachments in this email.")
        recs.append("🚨 DO NOT reply to this email or provide any personal/financial information.")
        recs.append("📞 If you already clicked a link or shared information, call 1930 immediately.")
        recs.append("🗑️ Delete this email after reporting it.")
    elif score >= 50:
        recs.append("⚠️ Treat this email as untrustworthy. Verify sender through official channels before acting.")
        recs.append("⚠️ Do not click links — manually type official website URLs instead.")
        recs.append("📧 Report this email to your IT/security team or to incident@cert-in.org.in")
    elif score >= 25:
        recs.append("🟡 Exercise caution. Verify sender identity independently before responding.")
        recs.append("🔍 Hover over any links to check the actual destination before clicking.")
    else:
        recs.append("✅ This email shows low risk indicators, but always remain vigilant.")
        recs.append("✅ Never share OTP, passwords, or banking PINs via email regardless of sender.")

    # Specific recommendations based on findings
    spf = components.get("spf", {})
    dkim = components.get("dkim", {})
    dmarc = components.get("dmarc", {})

    if not spf.get("is_safe", True) or not dkim.get("is_safe", True) or not dmarc.get("is_safe", True):
        recs.append(
            "🔐 Authentication checks (SPF/DKIM/DMARC) indicate this sender domain "
            "could not be fully verified — treat sender identity with suspicion."
        )

    base64_result = components.get("base64", {})
    if base64_result.get("has_hidden_payload"):
        recs.append(
            "🔎 Hidden Base64-encoded content was found containing scripts/URLs/HTML. "
            "This is a strong indicator of a deliberately obfuscated attack."
        )

    domain_ver = components.get("domain_verification", {})
    if domain_ver.get("is_phishing_domain"):
        recs.append(
            "🌐 Sender domain matches known phishing patterns — do not trust this sender."
        )

    recs.append("📋 To report this email officially, visit cybercrime.gov.in or call 1930.")

    return recs


def quick_risk_summary(analysis: dict) -> str:
    """One-line summary suitable for logs/audit trail."""
    return (
        f"{analysis['verdict']} (score={analysis['final_score']}/100) — "
        f"{analysis['total_findings']} findings, "
        f"{analysis['critical_count']} critical, "
        f"SPF={analysis['spf_label']}, DKIM={analysis['dkim_label']}, DMARC={analysis['dmarc_label']}"
    )
