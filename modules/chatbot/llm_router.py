# modules/chatbot/llm_router.py
# LLM routing: Ollama → Gemini → Local fallback
# Priority guaranteed. Never crashes. Never raises.

import logging
import re
import email
from email import policy
from email.parser import Parser
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy import — catch at call time, not import time
def _get_ollama():
    try:
        from modules.chatbot.ollama_client import is_ollama_running, query_ollama
        return is_ollama_running, query_ollama
    except ImportError as e:
        logger.warning(f"ollama_client import failed: {e}")
        return lambda: False, lambda *a, **kw: None

def _get_gemini():
    try:
        from modules.chatbot.gemini_client import query_gemini
        return query_gemini
    except ImportError as e:
        logger.warning(f"gemini_client import failed: {e}")
        return lambda *a, **kw: None

def _get_rag_fallback():
    try:
        from modules.chatbot.rag_engine import _offline_response
        return _offline_response
    except ImportError:
        return lambda q: (
            "🛡️ CyberSahayak is offline. "
            "For cyber crime emergencies, call **1930** or visit cybercrime.gov.in"
        )

def _extract_url(text: str):
    match = re.search(r'https?://[^\s]+', text)
    return match.group(0) if match else None

def _is_url_analysis_query(text: str):
    text = text.lower()

    triggers = [
        "analyze this url",
        "check this url",
        "scan this url",
        "analyse this url",
        "url analysis",
    ]

    return any(t in text for t in triggers)

def _is_whois_query(text: str):
    text = text.lower()

    triggers = [
        "whois",
        "domain info",
        "domain information",
        "check domain",
    ]

    return any(t in text for t in triggers)

def _is_dns_query(text: str):
    text = text.lower()

    triggers = [
        "dns",
        "dns records",
        "dns lookup",
        "check dns",
        "dns info",
    ]

    return any(t in text for t in triggers)
def _is_ip_query(text: str):
    text = text.lower()

    triggers = [
        "check ip",
        "analyze ip",
        "ip intel",
        "ip information",
    ]

    return any(t in text for t in triggers)
def _extract_ip(text: str):
    import re

    match = re.search(
        r'(?:\d{1,3}\.){3}\d{1,3}',
        text
    )

    return match.group(0) if match else None
def _is_email_query(text: str):
    text = text.lower()

    triggers = [
        "analyze this email",
        "check this email",
        "email analysis",
        "email scam",
        "phishing email",
    ]

    return any(t in text for t in triggers)

def _extract_domain(text: str):
    import re

    match = re.search(
        r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})',
        text
    )

    return match.group(1) if match else None


def route_llm_query(
    prompt: str,
    original_query: str = "",
    gemini_api_key: str = "",
    ollama_model: str = "phi3:mini",
) -> dict:
    """
    Route a prompt through available LLMs in priority order.

    Priority:
    1. Ollama (local, private, free)
    2. Gemini (cloud, requires API key)
    3. Local rule-based fallback

    Returns:
        {
            'response': str,
            'provider': 'ollama' | 'gemini' | 'local',
            'model': str,
            'success': bool,
        }
    """
    query_text = original_query or prompt

    if _is_url_analysis_query(query_text):
        from modules.url_analyzer.ml_model import predict_url

        url = _extract_url(query_text)

        if url:
            result = predict_url(url)

            findings = result.get("heuristic_findings", [])

            response = (
                f"🛡️ URL Analysis Result\n\n"
                f"URL: {url}\n"
                f"Verdict: {result.get('verdict','Unknown')}\n"
                f"Risk Score: {result.get('final_risk',0)}/100\n"
                f"ML Score: {result.get('ml_score',0)}/100\n\n"
            )

            if findings:
                response += "Findings:\n"
                for finding in findings:
                    response += f"• {finding}\n"

            response += (
                "\nRecommendation:\n"
                "Do NOT enter credentials, passwords, banking information, or OTPs on this website."
            )

            return {
                "response": response,
                "provider": "url_analyzer",
                "model": "local-tool",
                "success": True,
            }

    if _is_whois_query(query_text):
        try:
            from modules.url_analyzer.threat_intel import get_whois_intel

            domain = _extract_domain(query_text)

            if domain:

                result = get_whois_intel(domain)

                response = (
                    f"🌐 WHOIS Information\n\n"
                    f"Domain: {domain}\n"
                    f"Registrar: {result.get('registrar','Unknown')}\n"
                    f"Creation Date: {result.get('creation_date','Unknown')}\n"
                    f"Expiration Date: {result.get('expiration_date','Unknown')}\n"
                    f"Country: {result.get('registrant_country','Unknown')}\n"
                    f"Age (days): {result.get('age_days','Unknown')}\n"
                )

                return {
                    "response": response,
                    "provider": "whois_tool",
                    "model": "local-tool",
                    "success": True,
                }

        except Exception as e:
            logger.error(f"WHOIS tool failed: {e}")

    if _is_dns_query(query_text):
        try:
            from modules.url_analyzer.threat_intel import get_dns_intel

            domain = _extract_domain(query_text)

            if domain:

                result = get_dns_intel(domain)

                records = result.get("records", {})

                response = (
                    f"🌐 DNS Information\n\n"
                    f"Domain: {domain}\n"
                    f"Risk Score: {result.get('risk_score',0)}\n"
                    f"SPF Present: {result.get('has_spf',False)}\n"
                    f"DMARC Present: {result.get('has_dmarc',False)}\n\n"
                )

                for record_type, values in records.items():
                    response += f"{record_type} Records:\n"

                    for value in values[:5]:
                        response += f"• {value}\n"

                    response += "\n"

                return {
                    "response": response,
                    "provider": "dns_tool",
                    "model": "local-tool",
                    "success": True,
                }

        except Exception as e:
            logger.error(f"DNS tool failed: {e}")
    
    if _is_ip_query(query_text):
        try:
            from modules.url_analyzer.threat_intel import (
                get_geoip_intel,
                AbuseIPDBClient
            )

            ip = _extract_ip(query_text)

            if ip:
                geo = get_geoip_intel(ip)

                abuse_score = "Unknown"

                try:
                    abuse = AbuseIPDBClient()
                    result = abuse.check_ip(ip)

                    if isinstance(result, dict):
                        abuse_score = result.get(
                            "abuseConfidenceScore",
                            "Unknown"
                        )

                except Exception:
                    pass

                response = (
                    f"🌍 IP Intelligence Report\n\n"
                    f"IP: {ip}\n"
                    f"Country: {geo.get('country','Unknown')}\n"
                    f"City: {geo.get('city','Unknown')}\n"
                    f"ASN: {geo.get('asn','Unknown')}\n"
                    f"Abuse Score: {abuse_score}\n"
                )

                return {
                    "response": response,
                    "provider": "ip_tool",
                    "model": "local-tool",
                    "success": True,
                }
        except Exception as e:
            logger.error(f'IP tool failed: {e}')
            pass
    if _is_email_query(query_text):
        try:
            from modules.email_analyzer.email_risk_engine import analyze_email

            email_text = query_text

            msg = Parser(
                policy=policy.default
            ).parsestr(email_text)

            result = analyze_email(msg)

            response = (
                f"📧 Email Analysis Report\n\n"
                f"Verdict: {result.get('verdict','Unknown')}\n"
                f"Risk Score: {result.get('final_score',0)}/100\n"
                f"URLs Found: {result.get('url_count',0)}\n"
                f"Attachments: {result.get('attachment_count',0)}\n\n"
            )

            findings = result.get("all_findings", [])

            if findings:

                response += "Key Findings:\n"

                for finding in findings[:10]:

                    response += (
                        f"• {finding.get('description','')}\n"
                    )

            return {
                "response": response,
                "provider": "email_tool",
                "model": "local-tool",
                "success": True,
            }

        except Exception as e:

            logger.error(f"Email tool failed: {e}")

    # ── Priority 1: Ollama ─────────────────────────────────────────────────
    try:
        is_ollama_running, query_ollama = _get_ollama()
        if is_ollama_running():
            logger.debug("Router: trying Ollama")
            response = query_ollama(prompt, model=ollama_model)
            if response:
                return {
                    'response': response,
                    'provider': 'ollama',
                    'model': ollama_model,
                    'success': True,
                }
            logger.warning("Router: Ollama returned empty response")
    except Exception as e:
        logger.warning(f"Router: Ollama error: {e}")

    # ── Priority 2: Gemini ─────────────────────────────────────────────────
    if gemini_api_key and gemini_api_key.strip():
        try:
            query_gemini = _get_gemini()
            logger.debug("Router: trying Gemini")
            response = query_gemini(prompt, api_key=gemini_api_key)
            if response:
                return {
                    'response': response,
                    'provider': 'gemini',
                    'model': 'gemini-2.0-flash',
                    'success': True,
                }
            logger.warning("Router: Gemini returned empty response")
        except Exception as e:
            logger.warning(f"Router: Gemini error: {e}")

    # ── Priority 3: Local rule-based fallback ──────────────────────────────
    logger.info("Router: using local fallback")
    offline_response = _get_rag_fallback()
    query_text = original_query or prompt[:200]
    response = offline_response(query_text)

    return {
        'response': response,
        'provider': 'local',
        'model': 'rule-based',
        'success': False,
    }


def get_provider_status(gemini_api_key: str = "") -> dict:
    """
    Check status of all providers.
    Returns dict with status for display in UI.
    """
    status = {}

    # Ollama
    try:
        is_ollama_running, _ = _get_ollama()
        from modules.chatbot.ollama_client import get_available_models
        if is_ollama_running():
            models = get_available_models()
            status['ollama'] = {
                'available': True,
                'models': models,
                'label': f"✅ Online ({len(models)} model(s))",
            }
        else:
            status['ollama'] = {
                'available': False,
                'models': [],
                'label': "⚠️ Offline (server not running)",
            }
    except Exception as e:
        status['ollama'] = {
            'available': False,
            'models': [],
            'label': f"❌ Error: {e}",
        }

    # Gemini
    if gemini_api_key and gemini_api_key.strip():
        status['gemini'] = {
            'available': True,
            'label': "✅ Configured",
        }
    else:
        status['gemini'] = {
            'available': False,
            'label': "💡 Add GEMINI_API_KEY to .env",
        }

    # Local fallback always available
    status['local'] = {
        'available': True,
        'label': "✅ Always available",
    }

    return status
