# modules/chatbot/gemini_client.py
# Gemini API client — tries google.generativeai SDK first, falls back to REST.
# Never crashes. Returns None on failure for the router to handle.

import json
import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── SDK availability ───────────────────────────────────────────────────────
try:
    import google.generativeai as _genai
    _SDK_AVAILABLE = True
except ImportError:
    _genai = None
    _SDK_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────
_GEMINI_MODEL = "gemini-2.0-flash"
_GEMINI_REST_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{_GEMINI_MODEL}:generateContent"
)
_TIMEOUT = 30
_MAX_RETRIES = 2

_CYBER_SYSTEM = (
    "You are CyberSahayak, an expert Indian cybercrime prevention assistant. "
    "You help citizens identify scams, report cybercrime, and protect themselves online. "
    "You know Indian laws (IT Act 2000/2008), RBI/TRAI guidelines, and common India-specific "
    "frauds: digital arrest scams, UPI fraud, OTP theft, fake government impersonation. "
    "Always respond in clear, simple language. For active victims, always say: "
    "CALL 1930 IMMEDIATELY and go to cybercrime.gov.in."
)


def query_gemini(prompt: str, api_key: str) -> Optional[str]:
    """
    Query Gemini. Returns response text or None on any failure.
    Tries SDK first, then REST API.
    """
    if not api_key or not api_key.strip():
        logger.debug("Gemini: no API key provided")
        return None

    # Attempt 1: SDK
    if _SDK_AVAILABLE:
        result = _query_via_sdk(prompt, api_key)
        if result is not None:
            return result
        logger.warning("Gemini SDK failed — trying REST")

    # Attempt 2: REST API
    return _query_via_rest(prompt, api_key)


def _query_via_sdk(prompt: str, api_key: str) -> Optional[str]:
    """Use google.generativeai SDK."""
    for attempt in range(_MAX_RETRIES):
        try:
            _genai.configure(api_key=api_key)
            model = _genai.GenerativeModel(
                _GEMINI_MODEL,
                system_instruction=_CYBER_SYSTEM,
            )
            resp = model.generate_content(
                prompt,
                generation_config=_genai.types.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=1024,
                ),
            )
            return resp.text
        except Exception as e:
            logger.warning(f"Gemini SDK attempt {attempt + 1} failed: {e}")
            if attempt < _MAX_RETRIES - 1:
                time.sleep(1.5 ** attempt)
    return None


def _query_via_rest(prompt: str, api_key: str) -> Optional[str]:
    """Use Gemini REST API directly."""
    payload = {
        "system_instruction": {
            "parts": [{"text": _CYBER_SYSTEM}]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 1024,
        }
    }

    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.post(
                _GEMINI_REST_URL,
                params={"key": api_key},
                json=payload,
                timeout=_TIMEOUT,
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
                logger.warning(f"Gemini REST: unexpected response shape: {data}")
                return None

            elif resp.status_code == 429:
                logger.warning(f"Gemini REST: rate limited (attempt {attempt + 1})")
                time.sleep(2 ** attempt)
                continue

            elif resp.status_code in (401, 403):
                logger.error(f"Gemini REST: invalid API key (HTTP {resp.status_code})")
                return None

            else:
                logger.warning(f"Gemini REST: HTTP {resp.status_code}: {resp.text[:200]}")
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(1)
                continue

        except requests.exceptions.Timeout:
            logger.warning(f"Gemini REST: timeout (attempt {attempt + 1})")
            if attempt < _MAX_RETRIES - 1:
                time.sleep(1)
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Gemini REST: connection error: {e}")
            return None
        except Exception as e:
            logger.error(f"Gemini REST: unexpected error: {e}")
            return None

    return None


def validate_api_key(api_key: str) -> tuple[bool, str]:
    """
    Quick validation of Gemini API key.
    Returns (is_valid, message).
    """
    if not api_key or not api_key.strip():
        return False, "No API key provided"
    if not api_key.startswith("AI"):
        return False, "API key format looks incorrect (should start with 'AI')"
    result = _query_via_rest("Say 'OK' in one word.", api_key)
    if result:
        return True, "Gemini API key is valid"
    return False, "Gemini API key validation failed"
