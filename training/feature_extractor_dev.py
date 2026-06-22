# training/feature_extractor_dev.py
# AND modules/url_analyzer/feature_extractor.py (same code — runtime version)

import re
import urllib.parse
import ipaddress
from datetime import datetime

LEGITIMATE_DOMAINS = {
    'google.com', 'sbi.co.in', 'hdfcbank.com', 'paytm.com', 'phonepe.com',
    'irctc.co.in', 'uidai.gov.in', 'incometax.gov.in', 'npci.org.in'
}

def extract_url_features(url: str) -> dict:
    """
    Extracts the SAME numerical features used during training.
    This function bridges the gap between training CSVs and runtime inference.
    """
    features = {}
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(':')[0].replace('www.', '')

        # === Length-based features ===
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['fragment_length'] = len(parsed.fragment)

        # === Count-based features ===
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['num_question'] = url.count('?')
        features['num_ampersand'] = url.count('&')
        features['num_equal'] = url.count('=')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special'] = sum(not c.isalnum() for c in url)

        # === Boolean features ===
        features['has_ip'] = int(_is_ip(domain))
        features['has_https'] = int(parsed.scheme == 'https')
        features['has_subdomain'] = int(domain.count('.') > 1)
        features['has_at_symbol'] = int('@' in url)
        features['has_double_slash'] = int('//' in parsed.path)
        features['has_port'] = int(':' in parsed.netloc)

        # === Domain-based features ===
        parts = domain.split('.')
        features['tld_length'] = len(parts[-1]) if parts else 0
        features['num_subdomains'] = max(0, domain.count('.') - 1)
        features['domain_entropy'] = _entropy(domain)

        # === Keyword features ===
        suspicious_words = ['login', 'verify', 'update', 'secure', 'bank',
                            'account', 'kyc', 'free', 'win', 'prize', 'admin']
        for word in suspicious_words:
            features[f'has_{word}'] = int(word in url.lower())

        features['is_shortened'] = int(any(s in domain for s in
                                           ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd']))

    except Exception:
        features = {k: 0 for k in features}

    return features

def _is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def _entropy(text: str) -> float:
    import math
    from collections import Counter
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())