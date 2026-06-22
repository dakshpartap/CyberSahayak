# modules/email_analyzer/base64_detector.py
# Detect, decode, and analyze Base64-encoded content for hidden phishing payloads.
# Finds: encoded URLs, encoded JavaScript, encoded HTML, encoded executables.

import re
import base64
import binascii
import logging

logger = logging.getLogger(__name__)

# Minimum length to consider a string a candidate Base64 blob (avoids false
# positives on short tokens like "Ag==" or random 4-char words).
MIN_B64_LENGTH = 20

# Standard Base64 alphabet pattern (also covers URL-safe variant)
_B64_CANDIDATE_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{20,}={0,2})|(?:[A-Za-z0-9\-_]{20,}={0,2})"
)

# data: URI with base64 payload
_DATA_URI_RE = re.compile(
    r"data:([\w/+.\-]+);base64,([A-Za-z0-9+/=\-_]+)",
    re.IGNORECASE,
)

# Patterns to detect in DECODED content
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_SCRIPT_RE = re.compile(
    r"<script[\s>]|javascript:|eval\(|document\.write|window\.location|"
    r"String\.fromCharCode|unescape\(|fetch\(|XMLHttpRequest|atob\(|btoa\(",
    re.IGNORECASE,
)
_HTML_RE = re.compile(
    r"<html|<body|<form|<iframe|<input|<a\s+href|<meta\s+http-equiv",
    re.IGNORECASE,
)
_PHISHING_KEYWORD_RE = re.compile(
    r"\b(password|login|verify|otp|cvv|pin|bank|account.?number|"
    r"credit.?card|aadhaar|kyc|update.?your|click.?here|signin)\b",
    re.IGNORECASE,
)
_EXECUTABLE_MAGIC = {
    b"MZ": "Windows PE executable (.exe/.dll)",
    b"\x7fELF": "Linux ELF executable",
    b"PK\x03\x04": "ZIP archive (could contain malware)",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "Legacy MS Office document (.doc/.xls)",
}


def find_base64_candidates(text: str) -> list[str]:
    """Find all Base64-looking substrings in text, deduplicated."""
    if not text:
        return []
    candidates = set()

    # data: URIs (highest confidence)
    for match in _DATA_URI_RE.finditer(text):
        candidates.add(match.group(2))

    # Generic Base64-looking blobs
    for match in _B64_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if len(candidate) >= MIN_B64_LENGTH:
            candidates.add(candidate)

    return list(candidates)


def is_likely_base64(s: str) -> bool:
    """Heuristic check: does this string look like real Base64, not just hex/words?"""
    if len(s) < MIN_B64_LENGTH:
        return False
    if len(s) % 4 not in (0, 2, 3):  # allow slight padding variance
        # still attempt — many real-world blobs are concatenated/wrapped
        pass

    # Must have decent character diversity (avoid "aaaaaaaaaa...")
    unique_chars = len(set(s))
    if unique_chars < 6:
        return False

    # Should not be a pure hex string masquerading (those are valid b64 too,
    # but very long pure-hex repeated patterns are usually hashes, not payloads)
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) in (32, 40, 56, 64, 96, 128):
        return False  # Looks like an MD5/SHA hash, not a payload

    return True


def decode_base64(candidate: str) -> tuple[bool, bytes, str]:
    """
    Attempt to decode a Base64 candidate.
    Returns (success, decoded_bytes, error_message).
    Tries standard and URL-safe alphabets, with padding correction.
    """
    cleaned = candidate.strip()

    # Try URL-safe variant if it contains - or _
    variants = []
    if "-" in cleaned or "_" in cleaned:
        variants.append(("urlsafe", cleaned))
    variants.append(("standard", cleaned))

    for kind, value in variants:
        for pad_attempt in range(3):
            padded = value + ("=" * pad_attempt)
            try:
                if kind == "urlsafe":
                    decoded = base64.urlsafe_b64decode(padded)
                else:
                    decoded = base64.b64decode(padded, validate=False)
                if decoded:
                    return True, decoded, ""
            except (binascii.Error, ValueError) as e:
                continue
    return False, b"", "Could not decode as valid Base64"


def analyze_decoded_content(decoded: bytes) -> dict:
    """Analyze decoded bytes for malicious indicators."""
    result = {
        "is_text": False,
        "is_binary": False,
        "decoded_text": "",
        "detected_type": "unknown",
        "contains_url": False,
        "urls_found": [],
        "contains_script": False,
        "script_indicators": [],
        "contains_html": False,
        "contains_phishing_keywords": False,
        "phishing_keywords_found": [],
        "is_executable": False,
        "executable_type": "",
    }

    # Check magic bytes for known executable/document signatures
    for magic, ftype in _EXECUTABLE_MAGIC.items():
        if decoded.startswith(magic):
            result["is_executable"] = True
            result["executable_type"] = ftype
            result["is_binary"] = True
            result["detected_type"] = ftype
            return result

    # Try to decode as text
    try:
        text = decoded.decode("utf-8")
        result["is_text"] = True
    except UnicodeDecodeError:
        try:
            text = decoded.decode("latin-1")
            result["is_text"] = True
            result["detected_type"] = "text (latin-1)"
        except Exception:
            result["is_binary"] = True
            result["detected_type"] = "binary (undetermined)"
            return result

    result["decoded_text"] = text[:2000]  # Cap stored text

    # URL detection
    urls = _URL_RE.findall(text)
    if urls:
        result["contains_url"] = True
        result["urls_found"] = list(set(urls))[:20]

    # Script detection
    script_matches = _SCRIPT_RE.findall(text)
    if script_matches:
        result["contains_script"] = True
        result["script_indicators"] = list(set(script_matches))[:10]

    # HTML detection
    if _HTML_RE.search(text):
        result["contains_html"] = True

    # Phishing keyword detection
    kw_matches = _PHISHING_KEYWORD_RE.findall(text)
    if kw_matches:
        result["contains_phishing_keywords"] = True
        result["phishing_keywords_found"] = list(set(m.lower() for m in kw_matches))[:15]

    if not result["detected_type"] or result["detected_type"] == "unknown":
        if result["contains_html"]:
            result["detected_type"] = "HTML content"
        elif result["contains_script"]:
            result["detected_type"] = "JavaScript/script content"
        elif result["contains_url"]:
            result["detected_type"] = "Text with URL(s)"
        else:
            result["detected_type"] = "Plain text"

    return result


def scan_text_for_base64(text: str) -> dict:
    """
    Full scan: find candidates, decode each, analyze, score.
    This is the main entry point for the module.
    """
    if not text or not text.strip():
        return _empty_result()

    candidates = find_base64_candidates(text)
    decoded_items = []
    risk_delta = 0
    findings = []

    for candidate in candidates:
        if not is_likely_base64(candidate):
            continue

        success, decoded_bytes, error = decode_base64(candidate)
        if not success:
            continue

        analysis = analyze_decoded_content(decoded_bytes)

        item = {
            "encoded_snippet": candidate[:80] + ("..." if len(candidate) > 80 else ""),
            "encoded_length": len(candidate),
            "decoded_length": len(decoded_bytes),
            **analysis,
        }
        decoded_items.append(item)

        # Score this item
        item_risk = 0
        if analysis["is_executable"]:
            findings.append({
                "severity": "CRITICAL",
                "description": f"Base64-encoded executable detected: {analysis['executable_type']}. "
                               "This is a strong malware indicator.",
            })
            item_risk += 50

        if analysis["contains_script"]:
            findings.append({
                "severity": "HIGH",
                "description": f"Base64-encoded JavaScript/script content found "
                               f"({len(analysis['script_indicators'])} indicator(s)): "
                               f"{', '.join(analysis['script_indicators'][:3])}",
            })
            item_risk += 30

        if analysis["contains_html"] and analysis["contains_phishing_keywords"]:
            findings.append({
                "severity": "CRITICAL",
                "description": "Base64-encoded HTML page containing phishing keywords "
                               f"({', '.join(analysis['phishing_keywords_found'][:5])}). "
                               "This is a hidden phishing page payload.",
            })
            item_risk += 40
        elif analysis["contains_html"]:
            findings.append({
                "severity": "MEDIUM",
                "description": "Base64-encoded HTML content found — could be a hidden form or page.",
            })
            item_risk += 15

        if analysis["contains_url"]:
            findings.append({
                "severity": "HIGH",
                "description": f"Base64-encoded URL(s) found, hidden from plain-text scanning: "
                               f"{', '.join(analysis['urls_found'][:3])}",
            })
            item_risk += 25

        if analysis["contains_phishing_keywords"] and not analysis["contains_html"]:
            findings.append({
                "severity": "MEDIUM",
                "description": f"Base64-decoded text contains phishing-related keywords: "
                               f"{', '.join(analysis['phishing_keywords_found'][:5])}",
            })
            item_risk += 20

        item["item_risk_score"] = min(item_risk, 100)
        risk_delta += item_risk

    has_hidden_payload = any(
        item.get("contains_script") or item.get("is_executable") or
        (item.get("contains_html") and item.get("contains_phishing_keywords"))
        for item in decoded_items
    )

    return {
        "base64_detected": len(decoded_items) > 0,
        "candidates_found": len(candidates),
        "successfully_decoded": len(decoded_items),
        "decoded_items": decoded_items,
        "findings": findings,
        "risk_delta": min(risk_delta, 100),
        "has_hidden_payload": has_hidden_payload,
    }


def scan_raw_base64_input(b64_text: str) -> dict:
    """
    Entry point for when the user directly pastes a Base64 string
    (not embedded in a larger email) — e.g., the 'Paste Base64 content' UI field.
    """
    if not b64_text or not b64_text.strip():
        return _empty_result()

    cleaned = re.sub(r"\s+", "", b64_text.strip())

    success, decoded_bytes, error = decode_base64(cleaned)
    if not success:
        return {
            "base64_detected": False,
            "candidates_found": 1,
            "successfully_decoded": 0,
            "decoded_items": [],
            "findings": [{
                "severity": "INFO",
                "description": f"Input could not be decoded as valid Base64: {error}",
            }],
            "risk_delta": 0,
            "has_hidden_payload": False,
            "decode_error": error,
        }

    # Reuse the same analysis pipeline by wrapping
    result = scan_text_for_base64(cleaned)
    if result["successfully_decoded"] == 0 and decoded_bytes:
        # Direct decode succeeded but candidate regex might not have isolated it cleanly
        analysis = analyze_decoded_content(decoded_bytes)
        item = {
            "encoded_snippet": cleaned[:80] + ("..." if len(cleaned) > 80 else ""),
            "encoded_length": len(cleaned),
            "decoded_length": len(decoded_bytes),
            **analysis,
        }
        result["decoded_items"] = [item]
        result["successfully_decoded"] = 1
        result["base64_detected"] = True
    return result


def _empty_result() -> dict:
    return {
        "base64_detected": False,
        "candidates_found": 0,
        "successfully_decoded": 0,
        "decoded_items": [],
        "findings": [],
        "risk_delta": 0,
        "has_hidden_payload": False,
    }
