# modules/url_analyzer/heuristics.py — India-specific URL heuristic rules
import re
import urllib.parse
from datetime import datetime

# Legitimate Indian government & banking TLDs/domains
GOV_DOMAINS = {
    'gov.in', 'nic.in', 'uidai.gov.in', 'incometax.gov.in',
    'irctc.co.in', 'npci.org.in', 'rbi.org.in', 'sebi.gov.in',
    'mca.gov.in', 'epfindia.gov.in', 'esic.nic.in'
}

LEGITIMATE_BANK_DOMAINS = {
    'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com',
    'axisbank.com', 'kotak.com', 'pnbindia.in', 'bankofbaroda.in',
    'canarabank.com', 'unionbankofindia.co.in', 'yesbank.in',
    'indusind.com', 'federalbank.co.in', 'idfcfirstbank.com'
}

LEGITIMATE_PAYMENTS = {
    'paytm.com', 'phonepe.com', 'gpay.app', 'bhimupi.org.in',
    'bhim.upi.org.in', 'razorpay.com', 'billdesk.com', 'ccavenue.com'
}

# Suspicious TLDs frequently used in India-targeted phishing
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.info', '.online', '.site', '.fun', '.icu', '.buzz',
    '.monster', '.rest', '.uno', '.vip', '.work', '.cyou'
}

# Brand names that fraudsters typosquat against
BRAND_TARGETS = [
    'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay',
    'irctc', 'uidai', 'aadhaar', 'aadhar', 'incometax', 'epf', 'epfo',
    'amazon', 'flipkart', 'myntra', 'snapdeal', 'jio', 'airtel',
    'postoffice', 'indiapost', 'railway', 'passport', 'visa'
]

HOMOGRAPH_SUBSTITUTIONS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '@': 'a', '!': 'i', '$': 's'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
    'ow.ly', 'short.link', 'rebrand.ly', 'cutt.ly', 'v.gd',
    'tiny.cc', 'shrinkme.io', 'shorten.link'
}


def run_heuristic_checks(url: str) -> dict:
    """
    Runs a battery of India-specific heuristic checks on a URL.
    Returns a dict with findings list and composite risk score.
    """
    findings = []
    risk_score = 0

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        domain_no_www = domain.replace('www.', '')
        full_url_lower = url.lower()
        tld = '.' + domain_no_www.split('.')[-1] if '.' in domain_no_www else ''
    except Exception as e:
        return {'findings': [f'URL parse error: {e}'], 'risk_score': 10, 'flags': []}

    flags = []

    # ── 1. URL Shortener ──────────────────────────────────────────────
    if any(s in domain_no_www for s in URL_SHORTENERS):
        findings.append('Shortened URL detected — destination is hidden')
        flags.append('SHORTENED_URL')
        risk_score += 30

    # ── 2. Suspicious TLD ─────────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        findings.append(f'Suspicious TLD "{tld}" — commonly used in phishing')
        flags.append('SUSPICIOUS_TLD')
        risk_score += 35

    # ── 3. Brand impersonation / typosquatting ────────────────────────
    for brand in BRAND_TARGETS:
        normalized = _normalize_homographs(domain_no_www)
        if brand in normalized and brand + '.' not in domain_no_www:
            # Brand name is in domain but not as the legitimate apex domain
            is_legit = any(domain_no_www.endswith(legit)
                           for legit in (GOV_DOMAINS | LEGITIMATE_BANK_DOMAINS | LEGITIMATE_PAYMENTS))
            if not is_legit:
                findings.append(f'Possible brand impersonation: "{brand}" in domain')
                flags.append('BRAND_IMPERSONATION')
                risk_score += 50
                break

    # ── 4. Government domain spoofing ─────────────────────────────────
    gov_keywords = ['gov', 'government', 'official', 'ministry', 'india',
                    'portal', 'scheme', 'yojana']
    if any(kw in domain_no_www for kw in gov_keywords):
        is_real_gov = any(domain_no_www.endswith(g) for g in GOV_DOMAINS)
        if not is_real_gov:
            findings.append('Fake government domain pattern — not a real .gov.in domain')
            flags.append('FAKE_GOVT_DOMAIN')
            risk_score += 60

    # ── 5. IP address as host ─────────────────────────────────────────
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(domain):
        findings.append('URL uses raw IP address — legitimate sites use domain names')
        flags.append('IP_AS_HOST')
        risk_score += 40

    # ── 6. Excessive subdomains ───────────────────────────────────────
    subdomain_count = domain.count('.') - 1
    if subdomain_count >= 3:
        findings.append(f'Excessive subdomains ({subdomain_count}) — phishing evasion tactic')
        flags.append('EXCESSIVE_SUBDOMAINS')
        risk_score += 25

    # ── 7. Misleading HTTPS ───────────────────────────────────────────
    if 'https' in domain_no_www:
        findings.append('Domain contains "https" as a word — deceptive trick')
        flags.append('DECEPTIVE_HTTPS')
        risk_score += 45

    # ── 8. @ symbol in URL ────────────────────────────────────────────
    if '@' in parsed.netloc:
        findings.append('@ symbol in URL — everything before @ is ignored by browser')
        flags.append('AT_SYMBOL')
        risk_score += 55

    # ── 9. Double slash redirect ──────────────────────────────────────
    if '//' in parsed.path:
        findings.append('Double slash in path — possible redirect exploit')
        flags.append('DOUBLE_SLASH')
        risk_score += 20

    # ── 10. Suspicious keywords in URL ───────────────────────────────
    PHISH_KEYWORDS = [
        'login', 'signin', 'verify', 'update', 'confirm', 'secure',
        'account', 'banking', 'payment', 'otp', 'kyc', 'suspend',
        'blocked', 'validate', 'authenticate', 'credential', 'reward',
        'winner', 'claim', 'prize', 'free', 'gift', 'lucky'
    ]
    found_keywords = [kw for kw in PHISH_KEYWORDS if kw in full_url_lower]
    if len(found_keywords) >= 2:
        findings.append(f'Multiple phishing keywords: {", ".join(found_keywords[:4])}')
        flags.append('PHISHING_KEYWORDS')
        risk_score += min(len(found_keywords) * 8, 40)

    # ── 11. Extremely long URL ────────────────────────────────────────
    if len(url) > 200:
        findings.append(f'Unusually long URL ({len(url)} chars) — may hide true destination')
        flags.append('LONG_URL')
        risk_score += 15

    # ── 12. Non-ASCII characters (IDN homograph) ─────────────────────
    try:
        url.encode('ascii')
    except UnicodeEncodeError:
        findings.append('Non-ASCII characters in URL — possible IDN homograph attack')
        flags.append('IDN_HOMOGRAPH')
        risk_score += 50

    return {
        'findings': findings,
        'risk_score': min(risk_score, 100),
        'flags': flags,
        'domain': domain_no_www,
        'is_shortened': 'SHORTENED_URL' in flags,
        'is_brand_spoof': 'BRAND_IMPERSONATION' in flags or 'FAKE_GOVT_DOMAIN' in flags,
    }


def _normalize_homographs(text: str) -> str:
    """Replace lookalike characters with their ASCII equivalents."""
    result = text
    for fake, real in HOMOGRAPH_SUBSTITUTIONS.items():
        result = result.replace(fake, real)
    return result