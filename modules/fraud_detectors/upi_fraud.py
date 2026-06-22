# modules/fraud_detectors/upi_fraud.py
import re

# UPI ID format: user@bankname (legitimate VPAs end with bank PSP handles)
LEGITIMATE_PSP_HANDLES = {
    'okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'ybl', 'ibl', 'axl',
    'paytm', 'apl', 'abc', 'waaxis', 'wahdfcbank', 'waicici', 'wasbi',
    'fbl', 'timecosmos', 'upi', 'sbi', 'hdfc', 'icici', 'axis', 'kotak'
}

SUSPICIOUS_VPA_PATTERNS = [
    r'@(freelancer|winner|prize|lucky|reward)',
    r'^(lend|borrow|loan)',
    r'(pm|cm|modi|president)@',  # Impersonation of political figures
]

def analyze_upi(upi_id: str = "", amount: int = 0,
                purpose: str = "") -> dict:
    findings = []
    risk_score = 0
    
    if upi_id:
        upi_lower = upi_id.lower().strip()
        
        # Check VPA format
        if '@' not in upi_lower:
            findings.append('Invalid UPI format — not a real VPA')
            risk_score += 50
        else:
            handle = upi_lower.split('@')[1]
            
            # Unknown/suspicious PSP handle
            if handle not in LEGITIMATE_PSP_HANDLES:
                findings.append(f'Unknown PSP handle: @{handle} — verify before paying')
                risk_score += 30
            
            # Suspicious VPA patterns
            for pattern in SUSPICIOUS_VPA_PATTERNS:
                if re.search(pattern, upi_lower):
                    findings.append(f'Suspicious VPA pattern detected: {upi_id}')
                    risk_score += 60
                    break
    
    # Amount-based analysis
    if amount > 0:
        if amount in [1, 2, 5, 10]:
            # Small "test" payments are used to verify VPA before large fraud
            findings.append('⚠️ Small test payment amount — scammers use ₹1-₹10 to verify UPI ID')
            risk_score += 20
        
        if amount > 50000:
            findings.append(f'High-value transaction: ₹{amount:,} — verify recipient independently')
            risk_score += 15
    
    # Purpose-based analysis
    if purpose:
        SUSPICIOUS_PURPOSES = ['advance', 'fee', 'processing', 'customs', 'bail',
                               'penalty', 'verification', 'registration', 'kyc']
        for term in SUSPICIOUS_PURPOSES:
            if term in purpose.lower():
                findings.append(f'Suspicious transaction purpose: "{term}" — legitimate services don\'t charge this way')
                risk_score += 35
                break
    
    return {
        'risk_score': min(risk_score, 100),
        'findings': findings,
        'verdict': 'HIGH RISK — Do NOT pay' if risk_score >= 60 else
                   'SUSPICIOUS — Verify independently' if risk_score >= 30 else
                   'Low risk detected'
    }