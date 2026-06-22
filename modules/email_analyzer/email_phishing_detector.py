# modules/email_analyzer/email_phishing_detector.py
# Detect phishing patterns in email content:
# urgency tactics, credential theft, suspicious links, impersonation,
# malicious attachments, and social engineering indicators.

import re
import logging
import email.message
from urllib.parse import urlparse
from modules.email_analyzer.email_parser import (
    extract_text_body, extract_html_body, get_all_urls, get_attachments
)

logger = logging.getLogger(__name__)

# ── Urgency / Pressure Tactics ─────────────────────────────────────────────
URGENCY_PATTERNS = [
    (r"\b(urgent|urgently)\b", "Urgency language", 8),
    (r"\bimmediate\s*(action|response|attention)\b", "Immediate action pressure", 10),
    (r"\b(within|in)\s+(24|48|72)\s+hours?\b", "Time pressure (hours)", 10),
    (r"\byour\s+account\s+(will\s+be\s+)?(blocked|suspended|terminated|deleted|closed)\b",
     "Account suspension threat", 15),
    (r"\bfinal\s+(notice|warning|reminder)\b", "Final warning language", 12),
    (r"\blast\s+chance\b", "Last chance pressure", 10),
    (r"\bact\s+now\b", "Act now pressure", 8),
    (r"\bexpires?\s+(today|soon|in\s+\d+\s+hours?)\b", "Expiry urgency", 10),
    (r"\byour\s+account\s+(has\s+been|is)\s+(compromised|hacked|accessed)\b",
     "Account compromise claim", 12),
    (r"\bsecurity\s+(alert|warning|breach|incident)\b", "Security alarm", 8),
    (r"\bunauthori[sz]ed\s+(access|login|activity)\b", "Unauthorized activity claim", 12),
]

# ── Credential Theft Patterns ──────────────────────────────────────────────
CREDENTIAL_THEFT_PATTERNS = [
    (r"\b(click|tap)\s+(here|this\s+link)\s+to\s+(verify|confirm|update|validate)\b",
     "Click-to-verify phishing", 20),
    (r"\bverify\s+your\s+(account|identity|email|mobile|phone|details)\b",
     "Verification request", 15),
    (r"\bupdate\s+your\s+(kyc|aadhar|aadhaar|pan|bank|payment|card)\b",
     "KYC/document update request", 20),
    (r"\b(enter|provide|share|submit)\s+your\s+(password|pin|otp|cvv|cvc|card\s+number|account\s+number)\b",
     "Credential solicitation", 25),
    (r"\bconfirm\s+your\s+(details|credentials|information|personal\s+data)\b",
     "Personal data confirmation request", 15),
    (r"\bsecure\s+your\s+account\b", "Fake account securing", 10),
    (r"\bdownload\s+our\s+(app|application|software|tool)\b", "App download prompt", 12),
    (r"\b(send|transfer|deposit)\s+(money|funds|rs\.?|inr|₹)\b",
     "Money transfer request", 25),
    (r"\b(prize|winner|won|lottery|congratulations)\b.*\b(claim|click|pay|transfer)\b",
     "Prize scam with action required", 30),
]

# ── Indian-specific Phishing Patterns ─────────────────────────────────────
INDIA_SPECIFIC_PATTERNS = [
    (r"\bkyc\s+(expired|expiring|update|pending|verification)\b", "KYC fraud", 20),
    (r"\baadhaar\s+(linked|link|update|verify|number)\b", "Aadhaar phishing", 15),
    (r"\bpan\s+(card\s+)?(update|verify|link|block)\b", "PAN card phishing", 15),
    (r"\b(epfo|pf|provident\s+fund)\s+(update|kyc|link)\b", "PF/EPFO fraud", 20),
    (r"\b(income\s+tax\s+)?(refund|itd?r)\s+(pending|credit|claim)\b", "Tax refund scam", 20),
    (r"\bvat\s+clearance\b", "Tax clearance scam", 20),
    (r"\bdigital\s+arrest\b", "Digital arrest scam", 35),
    (r"\b(cbi|ed|enforcement\s+directorate|police)\s+(notice|case|arrest|warrant)\b",
     "Government impersonation threat", 30),
    (r"\b1930\b.*\b(case|arrest|fraud)\b", "Fake 1930 helpline impersonation", 25),
    (r"\b(neft|rtgs|imps|upi)\s*(transfer|payment|send)\b", "UPI/Bank transfer request", 15),
    (r"\bsend\s+to\s+upi\b", "Direct UPI payment request", 20),
    (r"\bpm\s+(kisan|awas|ujjwala)\b.*\b(apply|register|claim|fee)\b", "Fake govt scheme", 20),
    (r"\b(job|employment)\s+(offer|opportunity).*\b(registration|fee|deposit)\b",
     "Job scam with fee", 25),
    (r"\binvestment.*\b(\d+%|double|triple)\b.*\b(return|profit|earn)\b",
     "Investment scam", 25),
]

# ── Suspicious Link Patterns ───────────────────────────────────────────────
SUSPICIOUS_URL_PATTERNS = [
    (r"(?<![a-z0-9])(?:sbi|hdfc|icici|axis|rbi|trai|uidai|sebi|npci)(?![a-z0-9]).*\.",
     "Financial/Gov brand in suspicious URL"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address in URL"),
    (r"(?:bit\.ly|t\.co|tinyurl|is\.gd|buff\.ly|ow\.ly|tiny\.cc|short\.io)",
     "URL shortener hiding destination"),
    (r"(?:secure|login|update|verify|account|confirm).*\.", "Action keyword in domain"),
    (r"\.(?:tk|ml|ga|cf|gq|xyz|top|click|bid|download|stream|win|faith|party)\b",
     "Suspicious TLD in URL"),
    (r"https?://[^/]*@", "URL with embedded credentials (@ symbol)"),
    (r"(?:data:|javascript:|vbscript:)", "Dangerous URL scheme"),
    (r"(?:\.exe|\.bat|\.ps1|\.vbs|\.js|\.scr|\.jar|\.hta)\b", "Executable file URL"),
    (r"[^\w]0[^\w]", "Zero substituting O in domain (homograph)"),
]

# ── Malicious Attachment Types ─────────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".hta", ".msi", ".dll", ".reg", ".lnk", ".pif",
    ".wsf", ".wsh", ".com", ".pif",
}
MEDIUM_RISK_EXTENSIONS = {
    ".doc", ".docm", ".xlsm", ".pptm",  # Macro-enabled Office
    ".docx", ".xlsx", ".pptx",           # Office with potential macros
    ".pdf",                              # PDF with JavaScript
    ".zip", ".rar", ".7z", ".tar.gz",   # Archives may contain malware
    ".iso", ".img",                      # Disk images
}


def detect_phishing(msg: email.message.EmailMessage) -> dict:
    """
    Comprehensive phishing detection on email content.
    Returns all findings, risk delta, and categorized results.
    """
    text_body = extract_text_body(msg)
    html_body = extract_html_body(msg)
    full_content = (text_body + " " + html_body).lower()

    subject = msg.get("Subject", "").lower()
    combined = subject + " " + full_content

    all_findings = []
    risk_delta = 0

    # ── Check urgency ──────────────────────────────────────────────────────
    urgency_findings = _match_patterns(combined, URGENCY_PATTERNS, "urgency")
    all_findings.extend(urgency_findings)
    risk_delta += sum(f["score"] for f in urgency_findings)

    # ── Check credential theft ─────────────────────────────────────────────
    cred_findings = _match_patterns(combined, CREDENTIAL_THEFT_PATTERNS, "credential_theft")
    all_findings.extend(cred_findings)
    risk_delta += sum(f["score"] for f in cred_findings)

    # ── Check India-specific patterns ──────────────────────────────────────
    india_findings = _match_patterns(combined, INDIA_SPECIFIC_PATTERNS, "india_specific")
    all_findings.extend(india_findings)
    risk_delta += sum(f["score"] for f in india_findings)

    # ── Analyze URLs ───────────────────────────────────────────────────────
    urls = get_all_urls(msg)
    url_findings, url_risk = _analyze_urls(urls)
    all_findings.extend(url_findings)
    risk_delta += url_risk

    # ── Analyze attachments ────────────────────────────────────────────────
    attachments = get_attachments(msg)
    att_findings, att_risk = _analyze_attachments(attachments)
    all_findings.extend(att_findings)
    risk_delta += att_risk

    # ── Detect display-name spoofing patterns in body ──────────────────────
    if _has_fake_sender_in_body(full_content):
        all_findings.append({
            "category": "social_engineering",
            "description": "Email body contains language designed to build false trust "
                           "('official', 'secure', 'legitimate') without proper authentication.",
            "score": 10,
        })
        risk_delta += 10

    # ── Count urgency signals ──────────────────────────────────────────────
    urgency_count = len([f for f in urgency_findings])
    if urgency_count >= 3:
        all_findings.append({
            "category": "urgency_overload",
            "description": f"Email contains {urgency_count} urgency/pressure tactics — "
                           "a hallmark of phishing emails designed to prevent rational thinking.",
            "score": 15,
        })
        risk_delta += 15

    return {
        "findings": all_findings,
        "risk_delta": min(risk_delta, 100),
        "urgency_count": urgency_count,
        "credential_theft_count": len(cred_findings),
        "india_threat_count": len(india_findings),
        "suspicious_urls": [f for f in url_findings],
        "dangerous_attachments": [f for f in att_findings],
        "urls_found": urls,
        "attachments_found": attachments,
        "total_findings": len(all_findings),
    }


def _match_patterns(text: str, patterns: list, category: str) -> list[dict]:
    """Match a list of (pattern, description, score) against text."""
    findings = []
    for pattern, description, score in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({
                    "category": category,
                    "description": description,
                    "pattern": pattern,
                    "score": score,
                })
        except re.error:
            pass
    return findings


def _analyze_urls(urls: list[str]) -> tuple[list[dict], int]:
    """Analyze URLs for phishing indicators."""
    findings = []
    risk_delta = 0

    if not urls:
        return [], 0

    for url in urls[:50]:  # Limit to 50 URLs
        url_lower = url.lower()
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            domain = url_lower

        for pattern, description in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                findings.append({
                    "category": "suspicious_url",
                    "description": f"{description}: {url[:100]}",
                    "url": url[:200],
                    "score": 15,
                })
                risk_delta += 15
                break  # One finding per URL

        # Check if URL uses HTTP (not HTTPS) for sensitive pages
        if url_lower.startswith("http://") and any(
            kw in url_lower for kw in ("login", "secure", "account", "bank", "pay", "verify")
        ):
            findings.append({
                "category": "suspicious_url",
                "description": f"Sensitive page URL uses insecure HTTP (not HTTPS): {url[:100]}",
                "url": url[:200],
                "score": 20,
            })
            risk_delta += 20

    return findings, min(risk_delta, 60)


def _analyze_attachments(attachments: list[dict]) -> tuple[list[dict], int]:
    """Analyze email attachments for malicious indicators."""
    findings = []
    risk_delta = 0

    for att in attachments:
        fname = att.get("filename", "").lower()
        if not fname:
            continue

        # Check extension
        for ext in DANGEROUS_EXTENSIONS:
            if fname.endswith(ext):
                findings.append({
                    "category": "malicious_attachment",
                    "description": f"Dangerous attachment type '{ext}': {att['filename']}. "
                                   "This file type can execute malware on your computer.",
                    "filename": att["filename"],
                    "score": 40,
                })
                risk_delta += 40
                break
        else:
            for ext in MEDIUM_RISK_EXTENSIONS:
                if fname.endswith(ext):
                    findings.append({
                        "category": "suspicious_attachment",
                        "description": f"Potentially risky attachment '{att['filename']}'. "
                                       "Office documents and archives can contain malware.",
                        "filename": att["filename"],
                        "score": 15,
                    })
                    risk_delta += 15
                    break

        # Double extension (e.g., document.pdf.exe)
        parts = fname.rsplit(".", 2)
        if len(parts) == 3:  # double extension
            findings.append({
                "category": "malicious_attachment",
                "description": f"Double file extension detected: '{att['filename']}'. "
                               "This is a classic malware disguise technique.",
                "filename": att["filename"],
                "score": 35,
            })
            risk_delta += 35

    return findings, min(risk_delta, 80)


def _has_fake_sender_in_body(content: str) -> bool:
    """Check for social engineering trust-building language."""
    trust_patterns = [
        r"\bthis\s+is\s+an\s+official\b",
        r"\bdo\s+not\s+(share|forward|show)\s+this\b",
        r"\bfor\s+security\s+purposes\b",
        r"\bkeep\s+this\s+confidential\b",
        r"\bdo\s+not\s+ignore\b",
    ]
    return any(re.search(p, content, re.IGNORECASE) for p in trust_patterns)
