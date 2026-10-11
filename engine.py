"""Combines the rule engine and the ML model into one verdict."""
from __future__ import annotations

from .checks import LEVEL_HIGH, LEVEL_MEDIUM, analyze
from . import ml

RULE_WEIGHT = 0.6
ML_WEIGHT = 0.4


def level_for(score: int) -> str:
    if score >= LEVEL_HIGH:
        return "high"
    if score >= LEVEL_MEDIUM:
        return "medium"
    return "low"


def scan(text: str) -> dict:
    """Full analysis used by the web app and the CLI."""
    text = text or ""
    report = analyze(text)
    try:
        prob = ml.phishing_probability(text)
        signals = ml.top_signals(text) if prob > 0.5 else []
    except Exception:  # model missing or broken: fall back to rules only
        prob, signals = None, []

    if prob is None:
        score = report.score
    else:
        score = round(RULE_WEIGHT * report.score + ML_WEIGHT * prob * 100)
    score = max(0, min(100, score))

    return {
        "score": score,
        "level": level_for(score),
        "rule_score": report.score,
        "ml_probability": None if prob is None else round(prob, 3),
        "ml_signals": signals,
        "urls": report.urls,
        "findings": [f.__dict__ for f in report.findings],
    }
