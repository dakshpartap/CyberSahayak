# modules/image_analyzer/qr_detector.py
import cv2
import numpy as np
from PIL import Image
import io
from pyzbar.pyzbar import decode  # pip install pyzbar

def extract_qr_from_image(image_bytes: bytes) -> list[dict]:
    """
    Extracts all QR codes from an image and returns decoded data.
    QR codes in scam images often contain malicious UPI IDs or URLs.
    """
    img_array = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    
    results = []
    decoded_objects = decode(img)
    
    for obj in decoded_objects:
        data = obj.data.decode('utf-8', errors='ignore')
        results.append({
            'type': obj.type,           # QRCODE, UPCE, etc.
            'data': data,
            'is_url': data.startswith('http'),
            'is_upi': data.startswith('upi://'),
            'bbox': obj.rect._asdict()
        })
    
    return results

# modules/image_analyzer/ocr_engine.py
import pytesseract  # pip install pytesseract
from PIL import Image
import io

SCAM_OCR_PATTERNS = [
    'your account has been suspended',
    'click here to verify',
    'otp', 'password', 'pin',
    'arrested', 'warrant', 'fir',
    'income tax department',
    'cyber crime division',
]

def extract_text_from_image(image_bytes: bytes) -> dict:
    """OCR an image and check extracted text for scam patterns."""
    img = Image.open(io.BytesIO(image_bytes))
    
    # Preprocess: grayscale + threshold for better OCR
    img_gray = img.convert('L')
    
    text = pytesseract.image_to_string(img_gray, lang='eng+hin')
    text_lower = text.lower()
    
    found_patterns = [p for p in SCAM_OCR_PATTERNS if p in text_lower]
    
    return {
        'extracted_text': text,
        'scam_patterns_found': found_patterns,
        'risk_from_ocr': min(len(found_patterns) * 20, 80)
    }