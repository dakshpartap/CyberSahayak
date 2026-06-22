# modules/email_analyzer/email_parser.py
# Parse email from multiple input types: .eml bytes, raw text, headers-only paste.
# Returns a normalized EmailMessage object and metadata dict.

import email
import email.policy
import email.parser
import re
import logging
from typing import Optional, Union

logger = logging.getLogger(__name__)


def parse_eml_bytes(raw_bytes: bytes) -> tuple[email.message.EmailMessage, dict]:
    """Parse raw .eml bytes into an EmailMessage."""
    try:
        msg = email.message_from_bytes(
            raw_bytes,
            policy=email.policy.default,
        )
        meta = {
            "parse_method": "eml_bytes",
            "parse_success": True,
            "error": None,
        }
        return msg, meta
    except Exception as e:
        logger.error(f"eml parse error: {e}")
        return _make_empty_message(), {
            "parse_method": "eml_bytes",
            "parse_success": False,
            "error": str(e),
        }


def parse_msg_bytes(raw_bytes: bytes) -> tuple[email.message.EmailMessage, dict]:
    """
    Parse Outlook .msg bytes into an EmailMessage.
    Requires the optional 'extract-msg' package. Fails gracefully if missing.
    """
    try:
        import extract_msg
    except ImportError:
        return _make_empty_message(), {
            "parse_method": "msg_bytes",
            "parse_success": False,
            "error": (
                "The 'extract-msg' package is not installed, so native .msg files "
                "cannot be parsed. Please open the email in Outlook and use "
                "'Save As' -> 'Email (.eml)' or paste the raw email headers/text instead."
            ),
        }

    import tempfile
    import os as _os

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name

        msg_obj = extract_msg.Message(tmp_path)

        # Build an RFC-822 style raw text from the parsed .msg fields
        headers_text = (
            f"From: {msg_obj.sender or ''}\n"
            f"To: {msg_obj.to or ''}\n"
            f"Cc: {msg_obj.cc or ''}\n"
            f"Subject: {msg_obj.subject or ''}\n"
            f"Date: {msg_obj.date or ''}\n"
            f"Message-ID: {msg_obj.messageId or ''}\n"
        )
        body_text = msg_obj.body or ""
        full_text = headers_text + "\n" + body_text

        parsed_msg, parse_meta = parse_raw_text(full_text)

        # Attach attachment metadata as a synthetic note (actual binary content
        # of .msg attachments is available via msg_obj.attachments if needed later)
        parse_meta["msg_attachment_count"] = len(msg_obj.attachments) if msg_obj.attachments else 0
        parse_meta["parse_method"] = "msg_bytes"

        try:
            msg_obj.close()
        except Exception:
            pass

        return parsed_msg, parse_meta

    except Exception as e:
        logger.error(f".msg parse error: {e}")
        return _make_empty_message(), {
            "parse_method": "msg_bytes",
            "parse_success": False,
            "error": f"Failed to parse .msg file: {e}",
        }
    finally:
        if tmp_path and _os.path.exists(tmp_path):
            try:
                _os.remove(tmp_path)
            except Exception:
                pass


def msg_parsing_available() -> bool:
    """Check if .msg file parsing is available (extract-msg installed)."""
    try:
        import extract_msg
        return True
    except ImportError:
        return False


def parse_raw_text(text: str) -> tuple[email.message.EmailMessage, dict]:
    """Parse raw email text (headers + body) pasted by user."""
    # Normalize line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        msg = email.message_from_string(
            text,
            policy=email.policy.default,
        )
        meta = {
            "parse_method": "raw_text",
            "parse_success": True,
            "error": None,
        }
        return msg, meta
    except Exception as e:
        logger.error(f"raw text parse error: {e}")
        return _make_empty_message(), {
            "parse_method": "raw_text",
            "parse_success": False,
            "error": str(e),
        }


def parse_headers_only(headers_text: str) -> tuple[email.message.EmailMessage, dict]:
    """
    Parse pasted email headers only (no body).
    Adds a blank line to terminate headers per RFC 2822.
    """
    text = headers_text.strip().replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" not in text:
        text += "\n\n"  # Add blank line to terminate headers
    return parse_raw_text(text)


def extract_text_body(msg: email.message.EmailMessage) -> str:
    """Extract plaintext body from email message."""
    body_parts = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if ct == "text/plain" and "attachment" not in disp:
                    try:
                        body_parts.append(
                            part.get_content() if hasattr(part, "get_content")
                            else part.get_payload(decode=True).decode("utf-8", errors="replace")
                        )
                    except Exception:
                        pass
        else:
            try:
                body_parts.append(
                    msg.get_content() if hasattr(msg, "get_content")
                    else msg.get_payload(decode=True).decode("utf-8", errors="replace") if msg.get_payload(decode=True) else ""
                )
            except Exception:
                body_parts.append(str(msg.get_payload() or ""))
    except Exception as e:
        logger.warning(f"Body extraction error: {e}")
    return "\n".join(body_parts).strip()


def extract_html_body(msg: email.message.EmailMessage) -> str:
    """Extract HTML body from email message."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        return (
                            part.get_content() if hasattr(part, "get_content")
                            else part.get_payload(decode=True).decode("utf-8", errors="replace")
                        )
                    except Exception:
                        pass
        elif msg.get_content_type() == "text/html":
            return msg.get_payload(decode=True).decode("utf-8", errors="replace") if msg.get_payload(decode=True) else ""
    except Exception:
        pass
    return ""


def get_attachments(msg: email.message.EmailMessage) -> list[dict]:
    """Return list of attachment metadata (name, type, size)."""
    attachments = []
    try:
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", ""))
            fname = part.get_filename()
            if "attachment" in disp or fname:
                payload = part.get_payload(decode=True)
                attachments.append({
                    "filename": fname or "unknown",
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload) if payload else 0,
                    "disposition": disp,
                })
    except Exception as e:
        logger.warning(f"Attachment extraction error: {e}")
    return attachments


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from text content."""
    if not text:
        return []
    url_pattern = re.compile(
        r"https?://[^\s<>\"')\]]+|"
        r"www\.[^\s<>\"')\]]+",
        re.IGNORECASE,
    )
    urls = url_pattern.findall(text)
    # Clean trailing punctuation
    cleaned = [u.rstrip(".,;:!?)>]\"'") for u in urls]
    return list(set(cleaned))


def extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from href/src attributes in HTML."""
    if not html:
        return []
    pattern = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    urls = pattern.findall(html)
    # Filter to actual HTTP URLs
    http_urls = [u for u in urls if u.lower().startswith(("http://", "https://", "//"))]
    return list(set(http_urls))


def get_all_urls(msg: email.message.EmailMessage) -> list[str]:
    """Get all URLs from both text and HTML parts."""
    text_body = extract_text_body(msg)
    html_body = extract_html_body(msg)
    urls = extract_urls_from_text(text_body) + extract_urls_from_html(html_body)
    return list(set(urls))


def _make_empty_message() -> email.message.EmailMessage:
    """Return an empty EmailMessage as fallback."""
    return email.message.EmailMessage()


def normalize_email_address(addr: str) -> tuple[str, str]:
    """
    Parse 'Display Name <email@domain.com>' into (display_name, email).
    Returns ('', raw_addr) if no display name found.
    """
    if not addr:
        return "", ""
    # Try to find <email> pattern
    m = re.match(r'^(.*?)\s*<([^>]+)>', addr.strip())
    if m:
        return m.group(1).strip().strip('"\''), m.group(2).strip()
    # Just an email address
    addr = addr.strip()
    if "@" in addr:
        return "", addr
    return addr, ""


def get_domain_from_email(email_addr: str) -> str:
    """Extract domain from email address."""
    if not email_addr or "@" not in email_addr:
        return ""
    return email_addr.split("@")[-1].lower().strip()
