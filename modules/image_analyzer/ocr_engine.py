# modules/image_analyzer/ocr_engine.py — OCR + scam pattern detection
import io
import re
from PIL import Image
import pytesseract

SCAM_OCR_PATTERNS = [
    (r'\byour\s+account\s+has\s+been\s+(suspended|blocked|deactivated)\b',
     'Account suspension threat', 75),
    (r'\bclick\s+here\s+to\s+(verify|update|confirm)\b',
     'Phishing call-to-action', 65),
    (r'\b(otp|one.?time.?password)\b',
     'OTP request in image', 70),
    (r'\b(password|pin)\b.{0,30}\b(enter|provide|share|send)\b',
     'Credential request', 80),
    (r'\b(arrested|warrant|fir|non.bailable)\b',
     'Legal threat language', 85),
    (r'\b(income\s+tax|cyber\s+crime|cbi|trai|narcotics)\b',
     'Authority impersonation', 85),
    (r'\bcongratulations.{0,50}(won|winner|prize|selected)\b',
     'Fake prize notification', 80),
    (r'\b(kyc|aadhaar|aadhar).{0,50}(expire|update|verify|link)\b',
     'KYC fraud', 80),
    (r'\b(upi|paytm|phonepe|gpay).{0,50}(pay|send|transfer)\b',
     'UPI payment request', 70),
    (r'\bloan.{0,60}(approved|instant|without\s+documents)\b',
     'Fake loan offer', 70),
    (r'\b(rs\.?|inr|₹)\s*\d[\d,]*\s*(crore|lakh|thousand)\b',
     'Large amount mentioned', 50),
    (r'\b1930\b.{0,100}(calling|we\s+are)',
     'Fake 1930 helpline impersonation', 90),
]

def extract_text_from_image(image_bytes: bytes) -> dict:
    """
    OCR an image and check extracted text for scam patterns.
    Supports English and Hindi (Devanagari).
    Returns extracted text, patterns found, and risk score.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))

        # Ensure RGB mode
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')

        # Preprocess: grayscale + slight resize for better OCR accuracy
        img_gray = img.convert('L')
        if max(img_gray.size) < 800:
            scale = 800 / max(img_gray.size)
            new_size = (int(img_gray.width * scale), int(img_gray.height * scale))
            img_gray = img_gray.resize(new_size, Image.LANCZOS)

        # Try English + Hindi; fall back to English only
        try:
            text = pytesseract.image_to_string(img_gray, lang='eng+hin',
                                               config='--psm 6')
        except Exception:
            text = pytesseract.image_to_string(img_gray, lang='eng',
                                               config='--psm 6')

        text_lower = text.lower()
        matched_patterns = []

        for pattern, description, risk in SCAM_OCR_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matched_patterns.append({
                    'description': description,
                    'risk': risk
                })

        max_risk = max((p['risk'] for p in matched_patterns), default=0)
        combined_risk = min(max_risk + (len(matched_patterns) - 1) * 5, 100) if matched_patterns else 0

        return {
            'extracted_text': text,
            'text_length': len(text.strip()),
            'scam_patterns_found': matched_patterns,
            'risk_from_ocr': combined_risk,
            'has_text': len(text.strip()) > 20,
            'language_detected': 'multilingual' if any(ord(c) > 2304 for c in text) else 'english'
        }

    except Exception as e:
        return {
            'extracted_text': '',
            'text_length': 0,
            'scam_patterns_found': [],
            'risk_from_ocr': 0,
            'has_text': False,
            'error': str(e)
        }