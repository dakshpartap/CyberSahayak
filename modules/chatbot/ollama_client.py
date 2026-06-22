# modules/chatbot/ollama_client.py
# Ollama client with timeout, retry, graceful failure.
# Also exposes unified_llm_query for backward compatibility.

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────
OLLAMA_BASE = "http://localhost:11434"
FAST_MODEL = "phi3:mini"
ADVANCED_MODEL = "qwen3:8b"

DEFAULT_MODEL = FAST_MODEL
CONNECT_TIMEOUT = 3       # seconds to wait for connection
READ_TIMEOUT = 60         # seconds to wait for model response
MAX_RETRIES = 2

CYBER_SYSTEM_PROMPT = (
    "You are CyberSahayak, an expert Indian cybercrime prevention assistant. "
    "You help citizens identify scams, report cybercrime, and protect themselves online. "
    "You know Indian laws (IT Act 2000/2008), RBI/TRAI guidelines, and common India-specific "
    "frauds: digital arrest scams, UPI fraud, OTP theft, fake government impersonation. "
    "Always respond in clear, simple language. For active victims, always say: "
    "CALL 1930 IMMEDIATELY and go to cybercrime.gov.in."
)


def is_ollama_running() -> bool:
    """Check if Ollama server is reachable. Never raises."""
    try:
        resp = requests.get(
            f"{OLLAMA_BASE}/api/tags",
            timeout=(CONNECT_TIMEOUT, 5),
        )
        return resp.status_code == 200
    except Exception:
        return False


def get_available_models() -> list[str]:
    """Return list of pulled model names. Returns [] on any error."""
    try:
        resp = requests.get(
            f"{OLLAMA_BASE}/api/tags",
            timeout=(CONNECT_TIMEOUT, 5),
        )
        if resp.status_code == 200:
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        pass
    return []


def query_ollama(
    prompt: str,
    model: str = DEFAULT_MODEL,
    temperature: float = 0.3,
    max_tokens: int = 1024,
) -> Optional[str]:
    """
    Query a local Ollama model.
    Returns response string on success, None on any failure.
    Retries on transient errors.
    """
    payload = {
        "model": model,
        "system": CYBER_SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "top_p": 0.9,
        },
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(
                f"{OLLAMA_BASE}/api/generate",
                json=payload,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            if resp.status_code == 200:
                text = resp.json().get("response", "").strip()
                if text:
                    return text
                logger.warning("Ollama: empty response from model")
                return None
            else:
                logger.warning(f"Ollama: HTTP {resp.status_code} (attempt {attempt + 1})")

        except requests.exceptions.ConnectionError:
            # Ollama not running — no point retrying
            logger.debug("Ollama: connection refused (server not running)")
            return None
        except requests.exceptions.Timeout:
            logger.warning(f"Ollama: timeout (attempt {attempt + 1}/{MAX_RETRIES})")
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
        except Exception as e:
            logger.error(f"Ollama: unexpected error: {e}")
            return None

    return None


def unified_llm_query(
    prompt: str,
    gemini_api_key: str = "",
    original_query: str = "",
    model: str = DEFAULT_MODEL,
) -> dict:
    """
    Backward-compatible unified query. Internally uses llm_router.
    Returns {'response': str, 'provider': str, 'local': bool}.
    """
    try:
        from modules.chatbot.llm_router import route_llm_query
        result = route_llm_query(
            prompt=prompt,
            original_query=original_query,
            gemini_api_key=gemini_api_key,
            ollama_model=model,
        )
        return {
            'response': result.get('response', ''),
            'provider': result.get('provider', 'local'),
            'local': result.get('provider') in ('ollama', 'local'),
        }
    except Exception as e:
        logger.error(f"unified_llm_query error: {e}")
        # Ultimate fallback
        from modules.chatbot.rag_engine import _offline_response
        return {
            'response': _offline_response(original_query or prompt[:150]),
            'provider': 'local',
            'local': True,
        }
