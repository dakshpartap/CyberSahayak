# modules/sms_analyzer/local_classifier.py
import joblib
import re
from pathlib import Path

_pipeline = None

INDIA_HIGH_RISK_PATTERNS = [
    (r'\b(digital\s+arrest|arrested\s+online|cyber\s+police)\b',
     'Digital arrest scam keyword', 95),
    (r'\b(otp|one.time.password)\b.{0,30}\b(share|send|give|tell)\b',
     'OTP sharing request', 90),
    (r'\bupi\s+id\b.{0,50}\bsend\b', 'UPI payment request', 80),
    (r'\b(lottery|jackpot|won|winner).{0,30}\b(crore|lakh|rupee|rs\.?)\b',
     'Lottery scam', 85),
    (r'\b(aadhaar|aadhar|pan\s+card)\b.{0,50}\b(update|verify|expire|link)\b',
     'ID document scam', 80),
    (r'\byour\s+(kyc|account|sim|mobile).{0,30}(suspend|block|deactivat)',
     'Account suspension threat', 75),
    (r'bit\.ly|tinyurl|is\.gd|goo\.gl|short\.link',
     'Shortened URL in SMS', 60),
    (r'\b(cbse|jee|neet)\b.{0,50}\b(result|mark|admission)\b',
     'Fake exam result scam', 70),
    (r'\bwhatsapp\b.{0,40}\b(video|call).{0,40}\b(leak|viral|share)\b',
     'Sextortion via WhatsApp', 90),
]

def load_model():
    global _pipeline
    if _pipeline is None:
        _pipeline = joblib.load('models/sms_pipeline.pkl')

def analyze_sms_local(text: str) -> dict:
    """
    Stage 1: Fast local analysis — no API call needed.
    Returns result with confidence. If confidence is low, caller
    should escalate to LLM analysis.
    """
    load_model()
    
    text_clean = text.lower().strip()
    
    # Rule-based pass (high-confidence patterns)
    for pattern, flag_name, rule_score in INDIA_HIGH_RISK_PATTERNS:
        if re.search(pattern, text_clean, re.IGNORECASE):
            return {
                'risk_score': rule_score,
                'method': 'rule_engine',
                'flags': [flag_name],
                'confidence': 'High',
                'needs_llm': rule_score < 75  # only escalate borderline
            }
    
    # ML model pass
    proba = _pipeline.predict_proba([text_clean])[0]
    spam_prob = float(proba[1])
    risk_score = int(spam_prob * 100)
    
    return {
        'risk_score': risk_score,
        'method': 'ml_model',
        'flags': ['ML: Probable scam pattern'] if spam_prob > 0.5 else [],
        'confidence': 'High' if abs(spam_prob - 0.5) > 0.3 else 'Low',
        'needs_llm': abs(spam_prob - 0.5) < 0.3  # escalate uncertain cases
    }