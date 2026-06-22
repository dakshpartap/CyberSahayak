# modules/sms_analyzer/llm_analyzer.py — LLM escalation for uncertain SMS cases
from modules.chatbot.ollama_client import unified_llm_query
from config import settings
import json
import re

SMS_ANALYSIS_PROMPT = """You are an expert Indian cybercrime analyst. Analyze the following SMS/message for fraud indicators.

MESSAGE:
{message}

Respond ONLY with a JSON object (no preamble, no markdown) in this exact format:
{{
  "is_scam": true/false,
  "risk_score": 0-100,
  "scam_type": "string describing scam type or 'legitimate'",
  "key_indicators": ["list", "of", "red", "flags"],
  "safe_to_ignore": true/false,
  "recommended_action": "string with advice for the user",
  "confidence": "High/Medium/Low"
}}

Rules:
- risk_score 0-25: Likely legitimate
- risk_score 26-50: Suspicious, needs caution
- risk_score 51-75: Probable scam
- risk_score 76-100: Confirmed scam pattern
- Be extra alert for: OTP sharing, UPI payments to strangers, digital arrest threats, KYC expiry threats
- For active victims (money already sent), always set recommended_action to include calling 1930"""

def analyze_with_llm(message: str) -> dict:
    """
    Escalate borderline SMS to LLM for deeper analysis.
    Used when rule engine and ML model are uncertain (confidence < 0.7).
    Returns structured dict with risk assessment.
    """
    prompt = SMS_ANALYSIS_PROMPT.format(message=message[:1000])
    gemini_key = settings.GEMINI_API_KEY

    try:
        result = unified_llm_query(prompt, gemini_api_key=gemini_key)
        raw_response = result.get('response', '{}')
        provider = result.get('provider', 'unknown')

        # Strip any markdown fences if present
        clean = re.sub(r'```(?:json)?', '', raw_response).strip()

        parsed = json.loads(clean)

        # Validate and sanitize expected fields
        return {
            'is_scam': bool(parsed.get('is_scam', False)),
            'risk_score': max(0, min(100, int(parsed.get('risk_score', 0)))),
            'scam_type': str(parsed.get('scam_type', 'Unknown'))[:100],
            'key_indicators': list(parsed.get('key_indicators', []))[:10],
            'safe_to_ignore': bool(parsed.get('safe_to_ignore', True)),
            'recommended_action': str(parsed.get('recommended_action', ''))[:500],
            'confidence': str(parsed.get('confidence', 'Low')),
            'provider': provider,
            'method': 'llm'
        }

    except json.JSONDecodeError:
        # LLM returned non-JSON — extract risk from text heuristically
        return {
            'is_scam': False,
            'risk_score': 0,
            'scam_type': 'Analysis failed',
            'key_indicators': [],
            'safe_to_ignore': True,
            'recommended_action': 'LLM analysis failed. Use rule-based result.',
            'confidence': 'Low',
            'method': 'llm_failed'
        }
    except Exception as e:
        return {
            'is_scam': False,
            'risk_score': 0,
            'scam_type': 'Error',
            'key_indicators': [str(e)],
            'safe_to_ignore': True,
            'recommended_action': 'Analysis unavailable. If suspicious, call 1930.',
            'confidence': 'Low',
            'method': 'error'
        }