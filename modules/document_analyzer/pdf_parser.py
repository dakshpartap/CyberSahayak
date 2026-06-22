# modules/document_analyzer/pdf_parser.py
import io
import re
import hashlib
from pathlib import Path

try:
    import pdfplumber          # pip install pdfplumber
    import fitz                # pip install pymupdf
except ImportError:
    pass

def analyze_pdf(pdf_bytes: bytes) -> dict:
    """Full forensic analysis of a PDF document."""
    result = {
        'hash_sha256': hashlib.sha256(pdf_bytes).hexdigest(),
        'metadata': {},
        'pages': 0,
        'links': [],
        'suspicious_links': [],
        'embedded_files': [],
        'javascript': False,
        'suspicious_keywords': [],
        'risk_score': 0,
        'findings': []
    }
    
    try:
        # === PyMuPDF for metadata and embedded content ===
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        result['pages'] = doc.page_count
        result['metadata'] = dict(doc.metadata)
        
        # Check for JavaScript
        for name in doc.get_pdf_catalog().keys():
            if 'JavaScript' in str(name) or 'JS' in str(name):
                result['javascript'] = True
                result['risk_score'] += 40
                result['findings'].append('🚩 JavaScript detected in PDF — possible exploit')
        
        # Extract embedded files
        for i in range(doc.embfile_count()):
            info = doc.embfile_info(i)
            result['embedded_files'].append(info.get('filename', 'Unknown'))
        
        # === pdfplumber for text and links ===
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            full_text = ''
            for page in pdf.pages:
                page_text = page.extract_text() or ''
                full_text += page_text
                
                # Extract hyperlinks
                for annotation in page.annots or []:
                    uri = annotation.get('uri', '')
                    if uri:
                        result['links'].append(uri)
        
        # Score suspicious links
        suspicious_tlds = ['.xyz', '.top', '.click', '.tk', '.ml', '.ga']
        for link in result['links']:
            if any(link.endswith(tld) for tld in suspicious_tlds):
                result['suspicious_links'].append(link)
                result['risk_score'] += 25
        
        # Keyword analysis on extracted text
        DANGEROUS_PHRASES = [
            'your account will be closed', 'click here to avoid',
            'verify your aadhaar', 'otp required', 'call immediately',
            'you have been selected', 'unclaimed prize'
        ]
        for phrase in DANGEROUS_PHRASES:
            if phrase.lower() in full_text.lower():
                result['suspicious_keywords'].append(phrase)
                result['risk_score'] += 15
                
    except Exception as e:
        result['findings'].append(f'Parse error: {str(e)}')
    
    result['risk_score'] = min(result['risk_score'], 100)
    return result