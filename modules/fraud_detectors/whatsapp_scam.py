# modules/fraud_detectors/whatsapp_scam.py
import re

WHATSAPP_SCAM_PATTERNS = [
    # Job scams (very common in India 2024-25)
    (r'\b(part[\s-]?time\s+job|work\s+from\s+home).{0,100}(per\s+day|daily\s+earning)',
     'Fake part-time job offer', 75),
    (r'\b(like\s+and\s+subscribe|watch\s+videos|click\s+ads).{0,80}(earn|money|payment)',
     'Fake task-based earnings scam', 80),
    
    # Investment/Ponzi
    (r'\b(double|triple|10x|100%\s+return|guaranteed\s+profit)',
     'Guaranteed returns — investment fraud', 85),
    (r'\b(crypto|bitcoin|usdt).{0,80}(profit|return|earn)',
     'Crypto investment scam', 75),
    
    # Family emergency
    (r'\b(mom|papa|bhai|didi|friend).{0,50}(accident|hospital|arrested|emergency)',
     'Fake family emergency scam', 70),
    (r'\bnew\s+number\b.{0,100}(save|note|whatsapp)',
     '"New number" impersonation tactic', 65),
    
    # Lottery/Prize
    (r'\b(congratulations|congrats).{0,80}(selected|chosen|winner|prize)',
     'Fake prize/lottery notification', 85),
    
    # Survey scams
    (r'\b(fill\s+survey|complete\s+form).{0,80}(earn|payment|reward)',
     'Fake survey payment scam', 70),
    
    # Sextortion
    (r'\b(video|photos?|screenshots?).{0,50}(send|share|viral|forward).{0,50}(pay|money|transfer)',
     'Sextortion threat', 92),
]

def analyze_whatsapp_message(message: str) -> dict:
    text = message.lower().strip()
    signals = []
    
    for pattern, description, base_score in WHATSAPP_SCAM_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            signals.append({'pattern': description, 'score': base_score})
    
    # Check for suspicious links in message
    urls = re.findall(r'http[s]?://[^\s]+', message)
    shortened = [u for u in urls if any(s in u for s in
                 ['bit.ly', 'tinyurl', 'wa.me', 't.me'])]
    
    if shortened:
        signals.append({'pattern': 'Shortened URL in WhatsApp message', 'score': 55})
    
    # Check for external redirect to Telegram
    if 'telegram' in text or 't.me/' in text:
        signals.append({'pattern': 'Redirects to Telegram — classic job/investment scam pattern', 'score': 65})
    
    if not signals:
        return {'is_scam': False, 'risk_score': 0, 'signals': []}
    
    max_score = max(s['score'] for s in signals)
    combined_score = min(max_score + len(signals) * 5, 100)
    
    return {
        'is_scam': combined_score >= 65,
        'risk_score': combined_score,
        'signals': signals,
        'urls_found': urls,
        'shortened_urls': shortened
    }