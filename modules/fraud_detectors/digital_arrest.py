# modules/fraud_detectors/digital_arrest.py
import re
from dataclasses import dataclass

@dataclass
class DigitalArrestSignal:
    pattern_name: str
    matched_text: str
    risk_contribution: int
    explanation: str

# Comprehensive pattern library for digital arrest scams
DIGITAL_ARREST_PATTERNS = [
    # Authority impersonation
    (r'\b(cbi|cia|trai|narcotics|customs|enforcement\s+directorate|ed)\b',
     'Central agency impersonation', 85,
     'Impersonates CBI/TRAI/ED — these agencies never contact via phone/WhatsApp'),
    
    (r'\b(digital\s+arrest|cyber\s+arrest|virtual\s+arrest)\b',
     'Digital arrest keyword', 95,
     '"Digital arrest" is not a real legal concept — it is a scam term'),
    
    (r'\b(aadhaar|aadhar).{0,50}(drug|parcel|package|contraband)',
     'Aadhaar linked to illegal parcel', 88,
     'Classic script: "Your Aadhaar number was used to send drugs"'),
    
    # Fear tactics
    (r'\b(warrant|fir|arrest\s+warrant|non.bailable)\b.{0,100}\b(issued|filed|registered)\b',
     'Fake warrant mention', 82,
     'Real warrants are served physically by uniformed officers, not via video call'),
    
    (r'\b(stay\s+on.?video|do\s+not\s+disconnect|keep\s+(camera|video)\s+on)\b',
     'Forced video call tactic', 80,
     'Keeping victim on video call is a control tactic used in digital arrest scams'),
    
    # Financial demands
    (r'\b(bail|surety|penalty|fine).{0,80}(transfer|pay|send|deposit)',
     'Fake bail payment demand', 90,
     'Courts collect fees in person — never via UPI/NEFT to individuals'),
    
    (r'\b(safe\s+account|protected\s+account|rbi\s+account|clear\s+account)\b',
     'Safe account trap', 88,
     '"Transfer to safe account" is how victims lose all savings'),
    
    (r'(1930|cybercrime\.gov\.in).{0,100}(calling\s+you|we\s+are)',
     'Impersonating helpline 1930', 95,
     '1930 is an inbound helpline — it never calls you outbound'),
]

def analyze_for_digital_arrest(text: str) -> dict:
    text_lower = text.lower()
    signals = []
    
    for pattern, name, score, explanation in DIGITAL_ARREST_PATTERNS:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            signals.append(DigitalArrestSignal(
                pattern_name=name,
                matched_text=match.group(0),
                risk_contribution=score,
                explanation=explanation
            ))
    
    if not signals:
        return {'is_digital_arrest': False, 'risk_score': 0, 'signals': []}
    
    max_score = max(s.risk_contribution for s in signals)
    is_arrest_scam = max_score >= 80 or len(signals) >= 2
    
    return {
        'is_digital_arrest': is_arrest_scam,
        'risk_score': max_score,
        'signals': [{'name': s.pattern_name, 'score': s.risk_contribution,
                     'explanation': s.explanation} for s in signals],
        'immediate_action': (
            '🚨 THIS IS A DIGITAL ARREST SCAM. Disconnect immediately. '
            'Call 1930. Do NOT transfer any money. '
            'Visit cybercrime.gov.in to file a report.'
        ) if is_arrest_scam else None
    }