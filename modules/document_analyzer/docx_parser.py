# modules/document_analyzer/docx_parser.py — DOCX forensic analysis
import io
import re
import hashlib
from pathlib import Path

try:
    from docx import Document
    from docx.oxml.ns import qn
except ImportError:
    Document = None

DANGEROUS_PHRASES = [
    'your account will be closed', 'click here to avoid',
    'verify your aadhaar', 'otp required', 'call immediately',
    'you have been selected', 'unclaimed prize', 'digital arrest',
    'fir registered', 'income tax raid', 'cyber crime notice',
    'transfer to safe account', 'upi id', 'pay immediately',
    'password', 'pin number', 'credit card number'
]

SUSPICIOUS_MACRO_PATTERNS = [
    r'AutoOpen', r'AutoExec', r'Document_Open',
    r'Shell\s*\(', r'CreateObject\s*\(',
    r'WScript\.Shell', r'cmd\.exe', r'powershell'
]


def analyze_docx(docx_bytes: bytes) -> dict:
    """
    Forensic analysis of a DOCX file.
    Checks for: embedded macros, suspicious links, phishing text, metadata.
    """
    result = {
        'hash_sha256': hashlib.sha256(docx_bytes).hexdigest(),
        'metadata': {},
        'word_count': 0,
        'links': [],
        'suspicious_links': [],
        'images': [],
        'has_macros': False,
        'macro_warnings': [],
        'suspicious_keywords': [],
        'findings': [],
        'risk_score': 0
    }

    if Document is None:
        result['findings'].append('python-docx not installed — install with: pip install python-docx')
        return result

    try:
        doc = Document(io.BytesIO(docx_bytes))

        # ── Metadata ──────────────────────────────────────────────────
        core = doc.core_properties
        result['metadata'] = {
            'author': str(core.author or ''),
            'created': str(core.created or ''),
            'modified': str(core.modified or ''),
            'last_modified_by': str(core.last_modified_by or ''),
            'title': str(core.title or ''),
            'subject': str(core.subject or '')
        }

        # ── Check for macros (vbaProject.bin inside zip) ──────────────
        import zipfile
        with zipfile.ZipFile(io.BytesIO(docx_bytes), 'r') as z:
            names = z.namelist()
            if 'word/vbaProject.bin' in names:
                result['has_macros'] = True
                result['risk_score'] += 50
                result['findings'].append('🚩 VBA Macro detected — macros can execute malicious code')

            # Check for macro code patterns in XML
            for name in names:
                if name.endswith('.xml') or name.endswith('.rels'):
                    try:
                        content = z.read(name).decode('utf-8', errors='ignore')
                        for pattern in SUSPICIOUS_MACRO_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                result['macro_warnings'].append(
                                    f'Suspicious pattern "{pattern}" in {name}'
                                )
                                result['risk_score'] += 20
                    except Exception:
                        continue

        # ── Extract text and check for phishing phrases ───────────────
        full_text = '\n'.join(para.text for para in doc.paragraphs)
        full_text_lower = full_text.lower()
        result['word_count'] = len(full_text.split())

        for phrase in DANGEROUS_PHRASES:
            if phrase.lower() in full_text_lower:
                result['suspicious_keywords'].append(phrase)
                result['risk_score'] += 15

        # ── Extract hyperlinks ────────────────────────────────────────
        SUSPICIOUS_TLDS = {'.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.pw'}
        for rel in doc.part.rels.values():
            if 'hyperlink' in rel.reltype:
                target = rel._target
                result['links'].append(target)
                if any(target.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
                    result['suspicious_links'].append(target)
                    result['risk_score'] += 25
                    result['findings'].append(f'Suspicious link: {target}')

        # ── Image count ───────────────────────────────────────────────
        for rel in doc.part.rels.values():
            if 'image' in rel.reltype:
                result['images'].append(rel._target)

        # ── Summarize findings ────────────────────────────────────────
        if result['suspicious_keywords']:
            result['findings'].append(
                f'Phishing phrases found: {", ".join(result["suspicious_keywords"][:5])}'
            )
        if result['suspicious_links']:
            result['findings'].append(
                f'{len(result["suspicious_links"])} suspicious link(s) detected'
            )
        if not result['findings']:
            result['findings'].append('No obvious threats detected in document')

    except Exception as e:
        result['findings'].append(f'DOCX parse error: {str(e)}')

    result['risk_score'] = min(result['risk_score'], 100)
    return result