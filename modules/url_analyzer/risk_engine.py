def calculate_final_risk(
ml_score: float,
features: dict,
heuristic_result: dict = None,
whois_risk: int = 0,
dns_risk: int = 0,
openphish_risk: int = 0,
vt_risk: int = 0,
):
    """
    Combines ML score + heuristics + threat intel.
    Returns final risk score and verdict.
    """

    risk = float(ml_score)

    if features.get("has_paypal"):
        risk += 20

    if features.get("has_login"):
        risk += 15

    if features.get("has_verify"):
        risk += 15

    if features.get("has_kyc"):
        risk += 20

    if features.get("is_xyz"):
        risk += 25

    if features.get("contains_base64"):
        risk += 30

    if features.get("contains_redirect"):
        risk += 25

    if heuristic_result:
        risk += heuristic_result.get("risk_score", 0) * 0.4

    risk += whois_risk
    risk += dns_risk
    risk += openphish_risk
    risk += vt_risk

    risk = max(0, min(risk, 100))

    if risk >= 80:
        verdict = "PHISHING"
    elif risk >= 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    return {
        "final_risk": round(risk, 1),
        "verdict": verdict,
    }