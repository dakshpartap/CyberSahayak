# modules/sms_analyzer/keyword_engine.py — Fast keyword-based SMS pre-filter
import re
from dataclasses import dataclass

@dataclass
class KeywordMatch:
    keyword: str
    category: str
    risk_contribution: int
    context: str  # surrounding text snippet

# Categorized keyword bank — India-specific
KEYWORD_BANK = {
    'otp_theft': {
        'keywords': [
            'otp', 'one time password', 'one-time password', 'verification code',
            'security code', 'authentication code', 'share.*otp', 'send.*otp',
            'tell.*otp', 'give.*otp', 'enter.*otp'
        ],
        'risk': 85,
        'description': 'OTP/verification code theft attempt'
    },
    'digital_arrest': {
        'keywords': [
            'digital arrest', 'cyber arrest', 'virtual arrest', 'online arrest',
            'you are arrested', 'fir registered', 'non-bailable warrant',
            'trai action', 'cbi calling', 'narcotics bureau', 'enforcement directorate'
        ],
        'risk': 95,
        'description': 'Digital arrest scam'
    },
    'upi_fraud': {
        'keywords': [
            'upi id', 'send.*money.*upi', 'transfer.*gpay', 'pay.*phonepe',
            'paytm.*immediately', 'neft.*urgently', 'imps.*now', 'upi.*pin',
            'collect request', 'payment request'
        ],
        'risk': 80,
        'description': 'UPI payment fraud'
    },
    'kyc_scam': {
        'keywords': [
            'kyc.*expire', 'kyc.*update', 'kyc.*pending', 'kyc.*verify',
            'aadhaar.*link', 'pan.*verify', 'account.*suspend', 'sim.*block',
            'service.*deactivate', 'mobile.*suspend'
        ],
        'risk': 80,
        'description': 'KYC/document fraud'
    },
    'lottery_prize': {
        'keywords': [
            'congratulations.*won', 'selected.*winner', 'prize.*claim',
            'lottery.*crore', 'jackpot.*lakh', 'lucky.*draw.*winner',
            'gift.*voucher.*rs', 'cash.*prize.*rupee'
        ],
        'risk': 85,
        'description': 'Lottery/prize scam'
    },
    'loan_fraud': {
        'keywords': [
            'instant.*loan.*approved', 'pre-approved.*loan', 'loan.*without.*documents',
            'processing.*fee.*loan', 'loan.*app.*download', 'low.*interest.*loan.*today'
        ],
        'risk': 75,
        'description': 'Loan fraud'
    },
    'job_scam': {
        'keywords': [
            'work from home.*earn', 'part time.*daily.*earning',
            'like.*subscribe.*earn', 'watch.*video.*payment',
            'data entry.*payment', 'typing.*work.*rs.*per.*hour'
        ],
        'risk': 75,
        'description': 'Fake job/task scam'
    },
    'investment_fraud': {
        'keywords': [
            'guaranteed.*return', 'double.*money', '100%.*profit', '10x.*return',
            'crypto.*profit', 'bitcoin.*earn', 'forex.*guaranteed',
            'stock.*tip.*sure', 'investment.*scheme.*return'
        ],
        'risk': 80,
        'description': 'Investment/Ponzi fraud'
    },
    'sextortion': {
        'keywords': [
            'video.*leak.*pay', 'photo.*viral.*send.*money',
            'screenshot.*forward.*pay', 'intimate.*video.*pay',
            'whatsapp.*video.*call.*recorded'
        ],
        'risk': 92,
        'description': 'Sextortion threat'
    },
    'impersonation': {
        'keywords': [
            'rbi.*calling', 'income tax.*notice', 'police.*calling.*case',
            'income.*tax.*raid', 'court.*summons', 'legal.*notice.*pay',
            'collector.*office.*fine'
        ],
        'risk': 88,
        'description': 'Authority/institution impersonation'
    }
}

def run_keyword_scan(text: str) -> dict:
    """
    Fast keyword pre-scan. Returns all matching categories and the highest risk score.
    Runs in microseconds — no ML model loaded.
    """
    text_lower = text.lower()
    matches = []
    max_risk = 0

    for category, config in KEYWORD_BANK.items():
        for kw_pattern in config['keywords']:
            try:
                match = re.search(kw_pattern, text_lower, re.IGNORECASE)
                if match:
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 20)
                    context_snippet = text[start:end].strip()
                    matches.append(KeywordMatch(
                        keyword=kw_pattern,
                        category=category,
                        risk_contribution=config['risk'],
                        context=context_snippet
                    ))
                    max_risk = max(max_risk, config['risk'])
                    break  # One match per category is enough
            except re.error:
                continue

    # Boost if multiple categories match
    unique_categories = {m.category for m in matches}
    combined_score = min(max_risk + (len(unique_categories) - 1) * 5, 100) if matches else 0

    return {
        'has_keywords': len(matches) > 0,
        'matched_categories': list(unique_categories),
        'top_matches': [
            {
                'category': m.category,
                'risk': m.risk_contribution,
                'context': m.context,
                'description': KEYWORD_BANK[m.category]['description']
            }
            for m in sorted(matches, key=lambda x: x.risk_contribution, reverse=True)[:5]
        ],
        'keyword_risk_score': combined_score,
        'is_high_risk': combined_score >= 75
    }