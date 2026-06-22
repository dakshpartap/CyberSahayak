# modules/image_analyzer/vision_analyzer.py — Full image analysis orchestrator
from modules.image_analyzer.qr_detector import extract_qr_from_image
from modules.image_analyzer.ocr_engine import extract_text_from_image
from modules.url_analyzer.heuristics import run_heuristic_checks
from modules.fraud_detectors.upi_fraud import analyze_upi
import re

def analyze_image(image_bytes: bytes, filename: str = '') -> dict:
    """
    Full image forensic pipeline:
    1. QR code extraction + analysis
    2. OCR text extraction + scam pattern detection
    3. URL/UPI analysis on extracted content
    4. Composite risk scoring

    Returns unified result dict.
    """
    result = {
        'filename': filename,
        'qr_codes': [],
        'ocr': {},
        'url_findings': [],
        'upi_findings': [],
        'risk_score': 0,
        'verdict': '',
        'findings': [],
        'evidence_text': ''
    }

    # ── Stage 1: QR Code Detection ────────────────────────────────────
    try:
        qr_results = extract_qr_from_image(image_bytes)
        result['qr_codes'] = qr_results

        for qr in qr_results:
            if qr.get('is_url'):
                url = qr['data']
                heuristic = run_heuristic_checks(url)
                result['url_findings'].append({
                    'url': url,
                    'source': 'qr_code',
                    'heuristic': heuristic
                })
                result['risk_score'] = max(result['risk_score'], heuristic['risk_score'])
                if heuristic['findings']:
                    result['findings'].extend([f"[QR URL] {f}" for f in heuristic['findings']])

            elif qr.get('is_upi'):
                # upi://pay?pa=VPAHERE&pn=Name&am=Amount
                upi_data = qr['data']
                vpa_match = re.search(r'pa=([^&]+)', upi_data)
                amount_match = re.search(r'am=([^&]+)', upi_data)
                vpa = vpa_match.group(1) if vpa_match else ''
                amount = float(amount_match.group(1)) if amount_match else 0

                upi_result = analyze_upi(upi_id=vpa, amount=int(amount))
                result['upi_findings'].append({
                    'raw_data': upi_data,
                    'vpa': vpa,
                    'amount': amount,
                    'analysis': upi_result
                })
                result['risk_score'] = max(result['risk_score'], upi_result['risk_score'])
                if upi_result['findings']:
                    result['findings'].extend([f"[QR UPI] {f}" for f in upi_result['findings']])

            else:
                # Generic QR — check for suspicious text content
                content = qr['data'].lower()
                if any(kw in content for kw in ['arrest', 'otp', 'fir', 'cbi', 'trai']):
                    result['findings'].append(f'Suspicious QR content: {qr["data"][:100]}')
                    result['risk_score'] = max(result['risk_score'], 70)

        if qr_results:
            result['findings'].insert(0, f'{len(qr_results)} QR code(s) detected in image')

    except Exception as e:
        result['findings'].append(f'QR analysis error: {str(e)}')

    # ── Stage 2: OCR Analysis ─────────────────────────────────────────
    try:
        ocr_result = extract_text_from_image(image_bytes)
        result['ocr'] = ocr_result
        result['evidence_text'] = ocr_result.get('extracted_text', '')

        if ocr_result.get('scam_patterns_found'):
            for pattern in ocr_result['scam_patterns_found']:
                result['findings'].append(f"[OCR] {pattern['description']}")
            result['risk_score'] = max(result['risk_score'], ocr_result['risk_from_ocr'])

        # Scan OCR text for URLs
        if ocr_result.get('extracted_text'):
            urls_in_text = re.findall(r'https?://[^\s]+', ocr_result['extracted_text'])
            for url in urls_in_text[:5]:  # Cap at 5 to avoid runaway
                h = run_heuristic_checks(url)
                if h['risk_score'] > 20:
                    result['url_findings'].append({
                        'url': url,
                        'source': 'ocr_text',
                        'heuristic': h
                    })
                    result['risk_score'] = max(result['risk_score'], h['risk_score'])
                    result['findings'].extend([f"[OCR URL] {f}" for f in h['findings']])

    except Exception as e:
        result['findings'].append(f'OCR analysis error: {str(e)}')

    # ── Stage 3: Final Verdict ────────────────────────────────────────
    score = result['risk_score']
    if score >= 75:
        result['verdict'] = '🔴 HIGH RISK — This image contains fraud indicators'
    elif score >= 45:
        result['verdict'] = '🟡 SUSPICIOUS — Verify before acting on this image'
    elif score >= 20:
        result['verdict'] = '🟠 CAUTION — Some suspicious elements found'
    else:
        result['verdict'] = '🟢 LIKELY SAFE — No obvious scam indicators'

    if not result['findings'] and score == 0:
        result['findings'].append('No QR codes or scam text patterns detected')

    return result