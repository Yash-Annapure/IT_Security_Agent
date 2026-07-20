from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split

from it_security_agent.labeling import FEATURES

FN_WEIGHT, FP_WEIGHT = 10, 1


def _risk_score(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fn, fp = cm[1][0], cm[0][1]
    return fn * FN_WEIGHT + fp * FP_WEIGHT


def _best_threshold(model, X_test, y_test):
    probs = model.predict_proba(X_test)[:, 1]
    grid = np.linspace(0.05, 0.95, 19)
    risks = [_risk_score(y_test, (probs >= t).astype(int)) for t in grid]
    best_risk = min(risks)
    # Multiple thresholds routinely tie for minimal risk (e.g. any gap between the two
    # classes' predicted probabilities produces a whole plateau of equally-good cutoffs -
    # this is the normal case, not an edge case, for a class-imbalance-aware classifier).
    # Picking the *first* tied threshold - the lowest one tried - throws away all of that
    # margin and lands on the most aggressive, least conservative end of the plateau: on
    # real data this meant borderline/collision-shaped matches with only weak evidence
    # still cleared the bar and were auto-confirmed instead of going to review_queue.
    # The middle of the tied plateau keeps the same risk score but the most margin.
    tied = [float(t) for t, r in zip(grid, risks) if r == best_risk]
    best_threshold = float(np.median(tied))
    return best_threshold, best_risk


def train_and_compare(df: pd.DataFrame, model_dir: Path, random_state=42):
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    X = df[FEATURES].astype(float)
    y = df["label_real_match"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=random_state, stratify=y)

    candidates = {
        "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "random_forest": RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=random_state),
    }
    results = {}
    for name, candidate in candidates.items():
        candidate.fit(X_train, y_train)
        threshold, risk = _best_threshold(candidate, X_test, y_test)
        results[name] = {"model": candidate, "threshold": threshold, "risk_score": risk}

    winner = min(results, key=lambda k: results[k]["risk_score"])
    winning_model, winning_threshold = results[winner]["model"], results[winner]["threshold"]

    for path in model_dir.glob("*.joblib"):
        path.unlink()
    joblib.dump(
        {"name": winner, "model": winning_model, "threshold": winning_threshold},
        model_dir / f"{winner}.joblib",
    )
    return {"results": results, "winner": winner, "threshold": winning_threshold}


def load_winning_model(model_dir: Path):
    model_dir = Path(model_dir)
    files = list(model_dir.glob("*.joblib"))
    if not files:
        raise FileNotFoundError(f"no trained model found in {model_dir} - run train_and_compare first")
    payload = joblib.load(files[0])
    return payload["name"], payload["model"], payload["threshold"]


def predict_confidence(model, candidate_signals: dict) -> float:
    row = pd.DataFrame([{f: candidate_signals.get(f, 0) for f in FEATURES}]).astype(float)
    return float(model.predict_proba(row)[0][1])
