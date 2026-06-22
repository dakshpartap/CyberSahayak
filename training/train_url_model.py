# training/train_url_model.py — Train URL phishing detection model
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.url_analyzer.feature_extractor import extract_url_features


def load_dataset() -> pd.DataFrame:
    datasets = []

    # Dataset 1
    p = Path("datasets/dataset_phishing.csv")
    if p.exists():
        df = pd.read_csv(p)

        if "url" in df.columns and "status" in df.columns:
            df = df[["url", "status"]].copy()
            df["label"] = (
                df["status"]
                .astype(str)
                .str.lower()
                .map({"phishing": 1, "legitimate": 0})
            )
            datasets.append(df[["url", "label"]])

    # Dataset 2
    p = Path("datasets/phishing_site_urls.csv")
    if p.exists():
        df = pd.read_csv(p)

        cols = [c.lower() for c in df.columns]

        if "url" in cols:
            url_col = df.columns[cols.index("url")]

            if "label" in cols:
                label_col = df.columns[cols.index("label")]

                tmp = pd.DataFrame({
                    "url": df[url_col],
                    "label": df[label_col]
                })

                datasets.append(tmp)

    # Dataset 3
    p = Path("datasets/malicious_phish.csv")
    if p.exists():
        df = pd.read_csv(p)

        cols = [c.lower() for c in df.columns]

        if "url" in cols:
            url_col = df.columns[cols.index("url")]

            label_col = None

            for c in df.columns:
                if c.lower() in ["type", "label", "status"]:
                    label_col = c
                    break

            if label_col:
                tmp = pd.DataFrame({
                    "url": df[url_col],
                    "label": (
                        df[label_col]
                        .astype(str)
                        .str.lower()
                        .apply(
                            lambda x: 0
                            if x in ["benign", "legitimate", "good"]
                            else 1
                        )
                    )
                })

                datasets.append(tmp)

    if not datasets:
        raise RuntimeError(
            "No phishing datasets found in datasets folder."
        )

    final_df = pd.concat(datasets, ignore_index=True)

    final_df = final_df.dropna(subset=["url", "label"])

    final_df["url"] = final_df["url"].astype(str)

    # Normalize labels from all datasets
    final_df["label"] = (
        final_df["label"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    print("Unique labels:")
    print(final_df["label"].unique())

    label_map = {
        "bad": 1,
        "phishing": 1,
        "malicious": 1,
        "malware": 1,
        "1": 1,

        "good": 0,
        "benign": 0,
        "legitimate": 0,
        "safe": 0,
        "0": 0,
    }

    final_df["label"] = final_df["label"].map(label_map)

    # Remove rows with unknown labels
    final_df = final_df.dropna(subset=["label"])

    final_df["label"] = final_df["label"].astype(int)

    print("\nLabel Distribution:")
    print(final_df["label"].value_counts())

    return final_df

def build_feature_matrix(urls: list[str]) -> tuple[np.ndarray, list[str]]:
    """Extract features for all URLs. Returns (X, feature_names)."""
    print(f"Extracting features from {len(urls)} URLs...")
    feature_dicts = [extract_url_features(url) for url in urls]
    feature_names = list(feature_dicts[0].keys())
    X = np.array([[d.get(k, 0) for k in feature_names] for d in feature_dicts])
    return X, feature_names


def train():
    Path('models').mkdir(exist_ok=True)

    df = load_dataset()
    print(f"Dataset: {len(df)} URLs — {df['label'].sum()} phishing, "
          f"{(df['label'] == 0).sum()} legitimate")

    df = df.dropna(subset=['url', 'label'])
    df['url'] = df['url'].astype(str).str.strip()

    X, feature_names = build_feature_matrix(df['url'].tolist())
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest
    model = RandomForestClassifier(
    n_estimators=800,
    max_depth=25,
    min_samples_split=3,
    min_samples_leaf=1,
   class_weight={
    0: 1,
    1: 2
},
    n_jobs=-1,
    random_state=42
)

    print("Training Random Forest...")
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv, scoring='f1')
    print(f"5-Fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Feature importance
    importances = sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:10]
    pd.DataFrame(
        importances,
        columns=["Feature", "Importance"]
    ).to_csv(
        "models/url_feature_importance.csv",
        index=False
    )
    print("\nTop 10 Features:")
    for feat, imp in importances:
        print(f"  {feat:30s}: {imp:.4f}")

    # Save
    joblib.dump(model, 'models/url_model.pkl')
    joblib.dump(scaler, 'models/url_scaler.pkl')
    joblib.dump(feature_names, 'models/url_feature_names.pkl')
    print("\n✅ Model saved to models/url_model.pkl")
    
    metrics = {
        "accuracy": float((y_pred == y_test).mean()),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "dataset_size": int(len(df)),
        "feature_count": int(len(feature_names))
    }

    joblib.dump(
        metrics,
        "models/url_metrics.pkl"
    )

if __name__ == '__main__':
    train()