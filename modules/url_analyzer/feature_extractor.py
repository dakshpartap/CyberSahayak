import math
import urllib.parse
import ipaddress
import re
from collections import Counter



LEGITIMATE_DOMAINS = {
    'google.com', 'sbi.co.in', 'hdfcbank.com', 'paytm.com', 'phonepe.com',
    'irctc.co.in', 'uidai.gov.in', 'incometax.gov.in', 'npci.org.in',
    'icicibank.com', 'axisbank.com', 'kotak.com', 'rbi.org.in', 'sebi.gov.in',
    'amazon.in', 'flipkart.com', 'indiapost.gov.in', 'epfindia.gov.in',
    'nsdl.co.in', 'cibil.com', 'onlinesbi.sbi', 'yesbank.in',
    'idfcfirstbank.com', 'pnbindia.in', 'bankofbaroda.in', 'canarabank.com',
    'unionbankofindia.co.in', 'indusind.com', 'federalbank.co.in',
    'razorpay.com', 'billdesk.com', 'ccavenue.com', 'gpay.app','google.co.in',
'accounts.google.com',
'microsoft.com',
'live.com',
'outlook.com',
'github.com',
'openai.com',
'chatgpt.com',
'amazon.com',
'aws.amazon.com',
'linkedin.com',
'facebook.com',
'instagram.com',
'x.com',
}

# Canonical feature names in training order.
# ml_model.py loads this to align runtime vectors with saved model expectations.
FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'query_length', 'fragment_length',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes', 'num_at',
    'num_question', 'num_ampersand', 'num_equal', 'num_digits', 'num_special',
    'has_ip', 'has_https', 'has_subdomain', 'has_at_symbol', 'has_double_slash',
    'has_port', 'tld_length', 'num_subdomains', 'domain_entropy',
    'has_login', 'has_verify', 'has_update', 'has_secure', 'has_bank',
    'has_account', 'has_kyc', 'has_free', 'has_win', 'has_prize', 'has_admin',
    'is_shortened', 'is_legitimate_domain', "has_paypal",
    "has_amazon","has_otp","num_tokens",
"avg_token_length",
"max_token_length",
"has_reward",
"has_gift",
"has_bonus",
"has_upi",
"has_payment",
"has_wallet",
"has_refund",
"has_invoice",
"has_tax",
"has_income",
"has_government",
"has_aadhaar",
"has_pan",
    "has_google",
    "has_microsoft",
    "has_apple",
    "has_sbi",
    "has_hdfc",
    "has_icici",
    "has_phonepe",
    "has_paytm",

    "is_xyz",
    "is_click",
    "is_top",

    "contains_base64",
    "contains_redirect",

    "digit_ratio",
    "special_ratio",

]

_SUSPICIOUS_WORDS = [
    'login',
    'verify',
    'update',
    'secure',
    'bank',
    'account',
    'kyc',
    'free',
    'win',
    'prize',
    'admin',
    'otp',
    'reward',
    'gift',
    'bonus',
    'upi',
    'payment',
    'wallet',
    'refund',
    'invoice',
    'tax',
    'income',
    'government',
    'aadhaar',
    'pan',
]

_URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
    'ow.ly', 'short.link', 'rebrand.ly', 'cutt.ly', 'v.gd',
    'tiny.cc', 'shrinkme.io', 'shorten.link',
}


def extract_url_features(url: str) -> dict:
    """
    Extracts the SAME numerical features used during training.
    Always returns a complete dict keyed by FEATURE_NAMES, defaulting to 0.
    Safe to call on malformed or empty URLs.
    """
    # Pre-initialise every feature to 0 — guarantees complete vector on any error.
    features: dict = {k: 0 for k in FEATURE_NAMES}

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        domain_no_www = domain.replace('www.', '')
        url_lower = url.lower()

        # Length-based
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['fragment_length'] = len(parsed.fragment)

        url_lower = url.lower()

        # Brand features
        features["has_paypal"] = int("paypal" in url_lower)
        features["has_amazon"] = int("amazon" in url_lower)
        features["has_google"] = int("google" in url_lower)
        features["has_microsoft"] = int("microsoft" in url_lower)
        features["has_apple"] = int("apple" in url_lower)

        features["has_sbi"] = int("sbi" in url_lower)
        features["has_hdfc"] = int("hdfc" in url_lower)
        features["has_icici"] = int("icici" in url_lower)
        features["has_phonepe"] = int("phonepe" in url_lower)
        features["has_paytm"] = int("paytm" in url_lower)

        # Count-based
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

        # Boolean
        features['has_ip'] = int(_is_ip(domain))
        features['has_https'] = int(parsed.scheme == 'https')
        features['has_subdomain'] = int(domain_no_www.count('.') > 1)
        features['has_at_symbol'] = int('@' in url)
        features['has_double_slash'] = int('//' in parsed.path)
        features['has_port'] = int(
            ':' in parsed.netloc and not parsed.netloc.endswith(':')
        )

        # Domain-based
        parts = domain_no_www.split('.')
        features['tld_length'] = len(parts[-1]) if parts else 0
        features['num_subdomains'] = max(0, domain_no_www.count('.') - 1)
        features['domain_entropy'] = _entropy(domain_no_www)

        tokens = re.split(r"[/._\-?=&]+", url_lower)
        tokens = [t for t in tokens if t]

        features["num_tokens"] = len(tokens)

        if tokens:
            lengths = [len(t) for t in tokens]
            features["avg_token_length"] = sum(lengths) / len(lengths)
            features["max_token_length"] = max(lengths)

        # Keyword features
        for word in _SUSPICIOUS_WORDS:
            features[f'has_{word}'] = int(word in url_lower)

        features['is_shortened'] = int(
            any(s in domain_no_www for s in _URL_SHORTENERS)
        )
        features['is_legitimate_domain'] = int(domain_no_www in LEGITIMATE_DOMAINS)

        # Suspicious TLDs
        parts = domain.split('.')
        tld = parts[-1] if parts else ''

        features["is_xyz"] = int(tld == "xyz")
        features["is_click"] = int(tld == "click")
        features["is_top"] = int(tld == "top")

        # Base64 detection
        features["contains_base64"] = int(
            re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url) is not None
        )

        # Redirect detection
        features["contains_redirect"] = int(
            "redirect" in url_lower
            or "redir" in url_lower
            or "url=" in url_lower
        )

        # Ratios
        features["digit_ratio"] = (
            features["num_digits"] / max(features["url_length"], 1)
        )
        features["special_ratio"] = (
            features["num_special"] / max(features["url_length"], 1)
        )

    except Exception:
        # features already fully zeroed — just return as-is
        pass

    return features


def _is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())