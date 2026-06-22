# training/evaluate_models.py — Evaluate all trained models
import sys
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))


def evaluate_url_model():
    print("=" * 60)
    print("URL MODEL EVALUATION")
    print("=" * 60)

    model_path = Path('models/url_model.pkl')
    if not model_path.exists():
        print("❌ URL model not found. Run: python training/train_url_model.py")
        return

    from modules.url_analyzer.ml_model import predict_url

    test_cases = [
        # (url, expected_label, description)
        ('https://sbi.co.in/home', 0, 'Legitimate SBI'),
        ('https://hdfcbank.com', 0, 'Legitimate HDFC'),
        ('https://paytm.com/pay', 0, 'Legitimate Paytm'),
        ('https://sbi-kyc-verify.xyz/login', 1, 'SBI phishing'),
        ('https://192.168.1.1/banking/login', 1, 'IP-based phishing'),
        ('http://bit.ly/win-prize-india', 1, 'Shortened prize scam'),
        ('https://uidai-update-aadhaar.ml', 1, 'Aadhaar phishing'),
        ('https://secure-hdfc-login.click/verify', 1, 'HDFC phishing'),
        ('https://incometax.gov.in/home', 0, 'Legitimate govt site'),
        ('https://irctc.co.in/nget/train-search', 0, 'Legitimate IRCTC'),
    ]

    print(f"\n{'URL':<50} {'Expected':<12} {'ML Score':<12} {'Result'}")
    print("-" * 90)

    correct = 0
    for url, expected, desc in test_cases:
        try:
            result = predict_url(url)
            predicted = 1 if result['is_phishing'] else 0
            is_correct = predicted == expected
            if is_correct:
                correct += 1
            status = "✅" if is_correct else "❌"
            label = "Phishing" if expected else "Legit"
            print(f"{url[:50]:<50} {label:<12} {result['ml_score']:<12.1f} {status} ({desc})")
        except Exception as e:
            print(f"{url[:50]:<50} Error: {e}")

    accuracy = correct / len(test_cases) * 100
    print(f"\nAccuracy on test cases: {correct}/{len(test_cases)} ({accuracy:.0f}%)")


def evaluate_sms_model():
    print("\n" + "=" * 60)
    print("SMS MODEL EVALUATION")
    print("=" * 60)

    model_path = Path('models/sms_pipeline.pkl')
    if not model_path.exists():
        print("❌ SMS model not found. Run: python training/train_sms_model.py")
        return

    from modules.sms_analyzer.local_classifier import analyze_sms_local

    test_cases = [
        ("Your SBI KYC is expiring. Click bit.ly/sbi-kyc to update now.", 1, "KYC phishing"),
        ("Dear customer, your OTP is 483920. Do not share with anyone.", 0, "Legitimate OTP"),
        ("You have been selected for digital arrest. Stay on video call.", 1, "Digital arrest"),
        ("Your IRCTC ticket PNR 1234567890 is confirmed for 15 June.", 0, "Legitimate IRCTC"),
        ("Congratulations! You won ₹50 lakh lottery. Pay ₹500 to claim.", 1, "Lottery scam"),
        ("Your PhonePe payment of ₹500 to Swiggy was successful.", 0, "Legitimate payment"),
        ("Work from home: earn ₹5000/day liking YouTube videos. Join now.", 1, "Task scam"),
        ("Your Amazon order #123456 has been shipped. Track at amazon.in", 0, "Legitimate Amazon"),
    ]

    print(f"\n{'Message':<65} {'Expected':<10} {'Score':<8} {'Result'}")
    print("-" * 95)

    correct = 0
    for msg, expected, desc in test_cases:
        try:
            result = analyze_sms_local(msg)
            predicted = 1 if result['risk_score'] >= 50 else 0
            is_correct = predicted == expected
            if is_correct:
                correct += 1
            status = "✅" if is_correct else "❌"
            label = "Scam" if expected else "Legit"
            print(f"{msg[:65]:<65} {label:<10} {result['risk_score']:<8} {status} ({desc})")
        except Exception as e:
            print(f"{msg[:65]:<65} Error: {e}")

    accuracy = correct / len(test_cases) * 100
    print(f"\nAccuracy on test cases: {correct}/{len(test_cases)} ({accuracy:.0f}%)")


def print_model_summary():
    print("\n" + "=" * 60)
    print("MODEL FILE SUMMARY")
    print("=" * 60)

    model_files = [
        ('models/url_model.pkl', 'URL Phishing Classifier'),
        ('models/url_scaler.pkl', 'URL Feature Scaler'),
        ('models/sms_pipeline.pkl', 'SMS Spam Pipeline'),
        ('models/sms_model.pkl', 'SMS Classifier'),
        ('models/sms_vectorizer.pkl', 'SMS TF-IDF Vectorizer'),
        ('models/GeoLite2-Country.mmdb', 'MaxMind GeoIP Database'),
    ]

    for path, name in model_files:
        p = Path(path)
        if p.exists():
            size_kb = p.stat().st_size / 1024
            print(f"✅ {name:<35} {size_kb:>10.1f} KB")
        else:
            print(f"❌ {name:<35} {'NOT FOUND':>12}")


if __name__ == '__main__':
    evaluate_url_model()
    evaluate_sms_model()
    print_model_summary()