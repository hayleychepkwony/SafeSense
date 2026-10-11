"""Machine-learning side of SafeSense.

A TF-IDF + logistic regression text classifier (scikit-learn). It learns which
words and phrases tend to appear in phishing messages and returns a probability.
Train with:  python -m safesense.ml
"""
from __future__ import annotations

import csv
import os

import joblib
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(ROOT, "data", "messages.csv")
MODEL_PATH = os.path.join(ROOT, "models", "phish_model.joblib")

_model = None


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True, strip_accents="unicode")),
        ("clf", LogisticRegression(max_iter=1000, C=2.0)),
    ])


def load_data(path: str = DATA_PATH) -> tuple[list[str], list[int]]:
    with open(path, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    return [r["text"] for r in rows], [int(r["label"]) for r in rows]


def train(save: bool = True) -> dict:
    texts, labels = load_data()
    x_tr, x_te, y_tr, y_te = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
    model = build_pipeline().fit(x_tr, y_tr)
    held_out = model.score(x_te, y_te)
    model = build_pipeline().fit(texts, labels)  # final model uses all data
    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(model, MODEL_PATH)
    return {"samples": len(texts), "held_out_accuracy": round(held_out, 3)}


def get_model() -> Pipeline:
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            train()
        _model = joblib.load(MODEL_PATH)
    return _model


def phishing_probability(text: str) -> float:
    """Probability (0..1) that the text is phishing, according to the model."""
    if not text or not text.strip():
        return 0.0
    return float(get_model().predict_proba([text])[0][1])


def top_signals(text: str, n: int = 5) -> list[str]:
    """Words/phrases in this text that pushed the model toward 'phishing'."""
    model = get_model()
    vec, clf = model.named_steps["tfidf"], model.named_steps["clf"]
    row = vec.transform([text])
    names = vec.get_feature_names_out()
    contrib = row.multiply(clf.coef_[0]).tocoo()
    pairs = sorted(zip(contrib.data, contrib.col), reverse=True)
    skip = ENGLISH_STOP_WORDS | {"http", "https", "ly", "com"}
    out: list[str] = []
    for v, c in pairs:
        term = names[c]
        if v > 0 and not all(w in skip for w in term.split()):
            out.append(term)
    return out[:n]


if __name__ == "__main__":
    print(train())
