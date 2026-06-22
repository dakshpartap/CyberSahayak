from pathlib import Path
from typing import Optional
from .heuristics import run_heuristic_checks
from .risk_engine import calculate_final_risk
from .openphish import check_openphish
from .urlhaus import check_urlhaus
import numpy as np

# Resolve paths relative to THIS FILE so they never depend on CWD.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = _PROJECT_ROOT / "models" / "url_model.pkl"
SCALER_PATH = _PROJECT_ROOT / "models" / "url_scaler.pkl"
FEATURE_NAMES_PATH = _PROJECT_ROOT / "models" / "url_feature_names.pkl"

from .feature_extractor import extract_url_features, FEATURE_NAMES

_model = None
_scaler = None
_trained_feature_names: Optional[list] = None


def model_available() -> bool:
    """Non-raising check — True when the trained model file exists on disk."""
    return MODEL_PATH.exists()


def _load() -> None:
    """
    Load model, scaler, and feature names from disk.
    Raises RuntimeError with a user-friendly message on failure.
    """
    global _model, _scaler, _trained_feature_names

    if _model is not None:
        return  # already loaded

    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"Model not found at {MODEL_PATH}. "
            "Run:  python training/train_url_model.py"
        )

    try:
        import joblib

        _model = joblib.load(MODEL_PATH)

        if SCALER_PATH.exists():
            _scaler = joblib.load(SCALER_PATH)

        if FEATURE_NAMES_PATH.exists():
            _trained_feature_names = joblib.load(FEATURE_NAMES_PATH)
        else:
            # Fallback: assume training used the current FEATURE_NAMES ordering
            _trained_feature_names = list(FEATURE_NAMES)

    except Exception as exc:
        # Reset so next call retries
        _model = None
        _scaler = None
        _trained_feature_names = None
        raise RuntimeError(f"Model failed to load: {exc}") from exc


from urllib.parse import urlparse

TRUSTED_ROOTS = {
    "google.com",
    "github.com",
    "openai.com",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
}


def predict_url(url: str) -> dict:
    """
    Returns ML-based phishing probability for a URL.

    Returns:
        {
            'ml_score': float (0–100),
            'is_phishing': bool,
            'confidence': 'High' | 'Medium' | 'Low',
            'top_features': list[str],
        }

    Raises:
        RuntimeError if model is unavailable or corrupted.
    """
    _load()
    features = extract_url_features(url)
    if check_openphish(url):
        return {
            "ml_score": 100,
            "final_risk": 100,
            "verdict": "KNOWN PHISHING (OpenPhish)",
            "is_phishing": True,
            "confidence": "High",
            "top_features": ["openphish_match"],
            "heuristic_score": 100,
            "heuristic_findings": [
                "URL found in OpenPhish feed"
            ],
            "vt_score": 0,
            "vt_malicious": 0,
            "vt_suspicious": 0,
        }
    if check_urlhaus(url):
        return {
            "ml_score": 100,
            "final_risk": 100,
            "verdict": "KNOWN MALWARE URL (URLHaus)",
            "is_phishing": True,
            "confidence": "High",
            "top_features": ["urlhaus_match"],
            "heuristic_score": 100,
            "heuristic_findings": [
                "URL found in URLHaus malware feed"
            ]
        }
    # Trusted domain override
    host = urlparse(url).netloc.lower()
    host = host.replace("www.", "")

    if host in TRUSTED_ROOTS:
        return {
            "ml_score": 1.0,
            "is_phishing": False,
            "confidence": "High",
            "top_features": ["trusted_root_domain"],
        }

    if features.get("is_legitimate_domain", 0) == 1:
        return {
            "ml_score": 1.0,
            "is_phishing": False,
            "confidence": "High",
            "top_features": ["trusted_domain"],
        }

    # Build feature vector aligned to the order the model was trained on
    X = np.array(
        [[features.get(k, 0) for k in _trained_feature_names]],
        dtype=np.float64,
    )

    if _scaler is not None:
        X = _scaler.transform(X)

    prob_array = _model.predict_proba(X)[0]
    # Class-1 (phishing) probability; handles both binary and OvR multi-class
    phishing_prob = float(prob_array[1]) if len(prob_array) > 1 else float(prob_array[0])

    # Feature importance — safe for any estimator type
    top_features: list = []
    if hasattr(_model, 'feature_importances_'):
        importances = _model.feature_importances_
        paired = sorted(
            zip(_trained_feature_names, importances),
            key=lambda x: x[1],
            reverse=True,
        )
        top_features = [f for f, _ in paired[:5]]
    elif hasattr(_model, 'coef_'):
        # LogisticRegression / LinearSVC — use absolute coefficient magnitude
        coefs = np.abs(_model.coef_[0])
        paired = sorted(
            zip(_trained_feature_names, coefs),
            key=lambda x: x[1],
            reverse=True,
        )
        top_features = [f for f, _ in paired[:5]]
    else:
        top_features = list(_trained_feature_names[:5])

    gap = abs(phishing_prob - 0.5)
    confidence = 'High' if gap > 0.35 else 'Medium' if gap > 0.15 else 'Low'

    ml_score = round(phishing_prob * 100, 1)

    try:
        heuristic_result = run_heuristic_checks(url)
        # VirusTotal
        from modules.url_analyzer.threat_intel import VirusTotalClient

        vt = VirusTotalClient()
        vt_result = vt.scan_url(url)

        risk_result = calculate_final_risk(
            ml_score=ml_score,
            features=features,
            heuristic_result=heuristic_result,
        )
        vt_score = vt_result.get("vt_risk_score", 0)

        risk_result["final_risk"] = max(risk_result.get("final_risk", 0), vt_score)

        if vt_result.get("malicious", 0) >= 5:
            risk_result["final_risk"] = max(risk_result.get("final_risk", 0), 95)
            risk_result["verdict"] = "KNOWN PHISHING"

        return {
            "ml_score": ml_score,
            "final_risk": risk_result.get("final_risk", 0),
            "verdict": risk_result.get("verdict", "UNKNOWN"),

            "vt_score": vt_score,
            "vt_malicious": vt_result.get("malicious", 0),
            "vt_suspicious": vt_result.get("suspicious", 0),

            "is_phishing": risk_result.get("final_risk", 0) >= 60,
            "confidence": confidence,
            "top_features": top_features,
            "heuristic_score": heuristic_result.get("risk_score", 0),
            "heuristic_findings": heuristic_result.get("findings", []),
        }

    except Exception:
        # If heuristics or VT unavailable, return ML-only result
        return {
            "ml_score": ml_score,
            "is_phishing": ml_score >= 50,
            "confidence": confidence,
            "top_features": top_features,
        }