# core/risk_engine.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class RiskSignal:
    source: str       # 'ml_model', 'virustotal', 'whois', 'heuristic', 'email_auth', 'email_phishing', 'base64', etc.
    score: int        # 0-100
    weight: float     # How much this source is trusted
    description: str  # Human-readable reason
    confidence: str   # 'High', 'Medium', 'Low'

# Source weights — tuned based on reliability
WEIGHTS = {
    'virustotal':      1.5,   # Most reliable — 70+ engines
    'abuseipdb':       1.2,
    'ml_model':        1.0,
    'rule_engine':      1.1,   # India-specific rules are very precise
    'whois':           0.8,
    'dns':             0.7,
    'heuristic':       0.6,
    'llm':             0.5,   # Lowest weight — can hallucinate
    'geoip':           0.4,
    # Email Intelligence sources
    'email_auth':      1.3,   # SPF/DKIM/DMARC — strong cryptographic signal
    'email_domain':    1.1,   # Domain verification / impersonation detection
    'email_phishing':  1.0,   # Content-based phishing pattern detection
    'email_header':    1.1,   # Header spoofing detection
    'base64':          0.9,   # Hidden payload detection
}


def compute_risk_score(signals: list[RiskSignal]) -> dict:
    """
    Weighted risk aggregation with explanation.
    Uses a non-linear combination to prevent single-source domination.
    """
    if not signals:
        return {'score': 0, 'verdict': 'Unknown', 'explanation': []}
    
    # Weighted average
    total_weight = sum(WEIGHTS.get(s.source, 0.5) for s in signals)
    weighted_sum = sum(
        s.score * WEIGHTS.get(s.source, 0.5) for s in signals
    )
    base_score = weighted_sum / total_weight if total_weight > 0 else 0
    
    # Boost if multiple high-confidence sources agree
    high_risk_count = sum(1 for s in signals if s.score >= 70)
    if high_risk_count >= 2:
        base_score = min(base_score * 1.15, 100)
    
    # Hard overrides — certain signals are decisive
    for s in signals:
        if s.source == 'virustotal' and s.score >= 80:
            base_score = max(base_score, 90)
            break
        if s.source == 'rule_engine' and s.score >= 90:
            base_score = max(base_score, 85)
            break
        if s.source == 'email_auth' and s.score >= 85:
            base_score = max(base_score, 80)
            break
    
    final_score = int(min(base_score, 100))
    
    # Verdict mapping
    if final_score >= 75:
        verdict = '🔴 HIGH RISK'
    elif final_score >= 45:
        verdict = '🟡 SUSPICIOUS'
    elif final_score >= 20:
        verdict = '🟠 CAUTION'
    else:
        verdict = '🟢 LIKELY SAFE'
    
    return {
        'score': final_score,
        'verdict': verdict,
        'explanation': [
            f"{s.source.upper()}: {s.score}/100 — {s.description}"
            for s in sorted(signals, key=lambda x: x.score, reverse=True)
        ],
        'top_signal': max(signals, key=lambda x: x.score * WEIGHTS.get(x.source, 0.5))
    }


# ── Email Intelligence Integration ──────────────────────────────────────────

EMAIL_VERDICT_THRESHOLDS = [
    (75, 'PHISHING / HIGH RISK', '🔴'),
    (50, 'PHISHING', '🟠'),
    (25, 'SUSPICIOUS', '🟡'),
    (0,  'SAFE', '🟢'),
]


def compute_email_score(
    auth_score: int = 0,
    domain_score: int = 0,
    header_score: int = 0,
    phishing_score: int = 0,
    base64_score: int = 0,
) -> dict:
    """
    Compute aggregate email risk score from component scores using the
    same weighted signal framework as the rest of the platform.

    Args:
        auth_score: Combined SPF/DKIM/DMARC risk delta (0-100)
        domain_score: Domain verification / impersonation risk delta (0-100)
        header_score: Header spoofing risk delta (0-100)
        phishing_score: Content-based phishing detection risk delta (0-100)
        base64_score: Hidden Base64 payload risk delta (0-100)

    Returns:
        dict with 'email_score', 'email_verdict', 'base64_score', 'explanation'
    """
    signals = []

    if auth_score > 0:
        signals.append(RiskSignal(
            source='email_auth',
            score=min(auth_score, 100),
            weight=WEIGHTS['email_auth'],
            description='SPF/DKIM/DMARC authentication anomalies detected',
            confidence='High',
        ))

    if domain_score > 0:
        signals.append(RiskSignal(
            source='email_domain',
            score=min(domain_score, 100),
            weight=WEIGHTS['email_domain'],
            description='Sender domain verification / impersonation indicators',
            confidence='High',
        ))

    if header_score > 0:
        signals.append(RiskSignal(
            source='email_header',
            score=min(header_score, 100),
            weight=WEIGHTS['email_header'],
            description='Email header spoofing indicators detected',
            confidence='Medium',
        ))

    if phishing_score > 0:
        signals.append(RiskSignal(
            source='email_phishing',
            score=min(phishing_score, 100),
            weight=WEIGHTS['email_phishing'],
            description='Phishing content patterns detected in body/URLs/attachments',
            confidence='Medium',
        ))

    if base64_score > 0:
        signals.append(RiskSignal(
            source='base64',
            score=min(base64_score, 100),
            weight=WEIGHTS['base64'],
            description='Hidden Base64-encoded payload detected',
            confidence='Medium',
        ))

    result = compute_risk_score(signals)
    email_score = result['score']

    email_verdict, emoji = _get_email_verdict(email_score)

    return {
        'email_score': email_score,
        'base64_score': min(base64_score, 100),
        'email_verdict': email_verdict,
        'email_verdict_full': f"{emoji} {email_verdict}",
        'explanation': result['explanation'],
    }


def _get_email_verdict(score: int) -> tuple[str, str]:
    for threshold, verdict, emoji in EMAIL_VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict, emoji
    return 'SAFE', '🟢'


def signals_from_email_analysis(analysis: dict) -> list[RiskSignal]:
    """
    Convert a modules.email_analyzer.email_risk_engine.analyze_email() result
    into a list of RiskSignal objects, for use with the platform-wide
    compute_risk_score() aggregator (e.g. when combining email risk with
    other case-level evidence in the Evidence Builder / SOC Dashboard).
    """
    signals = []
    component_scores = analysis.get('component_scores', {})

    mapping = {
        'spf': ('email_auth', 'SPF authentication result'),
        'dkim': ('email_auth', 'DKIM authentication result'),
        'dmarc': ('email_auth', 'DMARC authentication result'),
        'domain_verification': ('email_domain', 'Sender domain verification'),
        'header_spoofing': ('email_header', 'Header spoofing detection'),
        'phishing_content': ('email_phishing', 'Phishing content detection'),
        'base64': ('base64', 'Hidden Base64 payload detection'),
    }

    # Aggregate SPF/DKIM/DMARC into one email_auth signal (avoid triple counting)
    auth_scores = [
        component_scores.get(k, 0) for k in ('spf', 'dkim', 'dmarc')
    ]
    auth_avg = sum(auth_scores) / len(auth_scores) if auth_scores else 0
    if auth_avg > 0:
        signals.append(RiskSignal(
            source='email_auth',
            score=int(min(auth_avg, 100)),
            weight=WEIGHTS['email_auth'],
            description=f"SPF={analysis.get('spf_label','?')} DKIM={analysis.get('dkim_label','?')} "
                       f"DMARC={analysis.get('dmarc_label','?')}",
            confidence='High',
        ))

    for key in ('domain_verification', 'header_spoofing', 'phishing_content', 'base64'):
        score = component_scores.get(key, 0)
        if score > 0:
            source, desc = mapping[key]
            signals.append(RiskSignal(
                source=source,
                score=int(min(score, 100)),
                weight=WEIGHTS.get(source, 0.8),
                description=desc,
                confidence='Medium',
            ))

    return signals
