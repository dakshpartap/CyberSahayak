# training/train_sms_model.py
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import re

# India-specific preprocessing
INDIA_SCAM_TERMS = [
    'kyc', 'aadhaar', 'upi', 'paytm', 'phonepe', 'gpay', 'neft', 'imps',
    'cbse', 'lottery', 'jackpot', 'ott', 'emi', 'cibil', 'pan',
    'income tax', 'epf', 'pf', '1930', 'cyber crime'
]

def preprocess_sms(text: str) -> str:
    text = text.lower()
    text = re.sub(r'http\S+', ' URL ', text)
    text = re.sub(r'\d{10,}', ' PHONE ', text)
    text = re.sub(r'[^\w\s]', ' ', text)
    # Normalise India-specific terms
    for term in INDIA_SCAM_TERMS:
        text = text.replace(term, term.replace(' ', '_'))
    return text.strip()

def train():
    # Load and combine datasets
    df = pd.read_csv('datasets/SMS_Spam_Collection.csv', sep='\t',
                     names=['label', 'text'], encoding='latin-1')
    # Add your scam_keywords.csv as synthetic positives
    keywords_df = pd.read_csv('datasets/scam_keywords.csv')
    
    df['text'] = df['text'].apply(preprocess_sms)
    df['label_num'] = (df['label'] == 'spam').astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        df['text'], df['label_num'], test_size=0.2, stratify=df['label_num'],
        random_state=42
    )

    # Pipeline: TF-IDF (with n-grams) + Logistic Regression
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 3),        # unigrams + bigrams + trigrams
            max_features=20000,
            sublinear_tf=True,         # log TF scaling
            min_df=2
        )),
        ('clf', LogisticRegression(C=5.0, max_iter=1000, class_weight='balanced'))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluation
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Ham', 'Spam']))
    
    # Save both components separately for runtime use
    joblib.dump(pipeline.named_steps['tfidf'], 'models/sms_vectorizer.pkl')
    joblib.dump(pipeline.named_steps['clf'], 'models/sms_model.pkl')
    joblib.dump(pipeline, 'models/sms_pipeline.pkl')
    print("SMS model saved.")

if __name__ == '__main__':
    train()