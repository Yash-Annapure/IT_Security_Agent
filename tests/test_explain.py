import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from it_security_agent import explain, labeling

X = pd.DataFrame([{f: i % 2 for f in labeling.FEATURES} for i in range(20)])
y = pd.Series([i % 2 for i in range(20)])


def test_make_explainer_logistic_regression():
    lr = LogisticRegression().fit(X, y)
    explainer = explain.make_explainer("logistic_regression", lr, X)
    assert explainer is not None


def test_make_explainer_random_forest():
    rf = RandomForestClassifier(n_estimators=10).fit(X, y)
    explainer = explain.make_explainer("random_forest", rf, X)
    assert explainer is not None


def test_make_explainer_unknown_model_raises():
    with pytest.raises(ValueError):
        explain.make_explainer("unknown_model", object(), X)


def test_explain_match_returns_dict_keyed_by_feature():
    rf = RandomForestClassifier(n_estimators=10).fit(X, y)
    explainer = explain.make_explainer("random_forest", rf, X)
    row = X.iloc[[0]]
    result = explain.explain_match(explainer, row)
    assert set(result.keys()) == set(labeling.FEATURES)
