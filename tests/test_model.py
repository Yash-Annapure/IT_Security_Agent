import numpy as np
import pandas as pd
import pytest

from it_security_agent import labeling, model


def _synthetic_dataset(n=60, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        is_real = i % 2 == 0
        rows.append({
            "vendor_equals_package": int(is_real) if rng.random() > 0.2 else int(not is_real),
            "name_similarity": rng.uniform(0.7, 1.0) if is_real else rng.uniform(0.0, 0.5),
            "py_keyword_score": rng.integers(0, 5),
            "js_keyword_score": rng.integers(0, 5),
            "keyword_alignment": rng.integers(-3, 3),
            "ecosystem_pypi": 1,
            "osv_corroborated": int(is_real) if rng.random() > 0.3 else int(not is_real),
            "label_real_match": is_real,
        })
    return pd.DataFrame(rows)


def test_train_and_compare_returns_both_models_and_a_winner(tmp_path):
    df = _synthetic_dataset()
    result = model.train_and_compare(df, model_dir=tmp_path)
    assert set(result["results"].keys()) == {"logistic_regression", "random_forest"}
    assert result["winner"] in ("logistic_regression", "random_forest")
    assert 0.0 <= result["threshold"] <= 1.0


def test_train_and_compare_persists_model_file(tmp_path):
    df = _synthetic_dataset()
    model.train_and_compare(df, model_dir=tmp_path)
    saved_files = list(tmp_path.glob("*.joblib"))
    assert len(saved_files) == 1


def test_load_winning_model_round_trips(tmp_path):
    df = _synthetic_dataset()
    model.train_and_compare(df, model_dir=tmp_path)
    name, loaded_model, threshold = model.load_winning_model(model_dir=tmp_path)
    assert name in ("logistic_regression", "random_forest")
    assert hasattr(loaded_model, "predict_proba")


def test_registry_overlap_leakage_regression(tmp_path):
    # If registry_overlap leaked into FEATURES, a model trained where it perfectly
    # predicts the label would show near-1.0 accuracy. Assert FEATURES excludes it,
    # which is the actual guard - this test fails loudly if that guard is removed.
    assert "registry_overlap" not in labeling.FEATURES


def test_predict_confidence_returns_probability(tmp_path):
    df = _synthetic_dataset()
    model.train_and_compare(df, model_dir=tmp_path)
    _, loaded_model, _ = model.load_winning_model(model_dir=tmp_path)
    signals = {f: 0.5 for f in labeling.FEATURES}
    confidence = model.predict_confidence(loaded_model, signals)
    assert 0.0 <= confidence <= 1.0
