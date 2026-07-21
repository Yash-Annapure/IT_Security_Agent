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


def test_explain_matches_batches_without_changing_per_row_values():
    # The agent explains a whole review queue in one call; each row must get exactly the
    # contributions it would have got explained on its own.
    rf = RandomForestClassifier(n_estimators=10, random_state=0).fit(X, y)
    explainer = explain.make_explainer("random_forest", rf, X)
    rows = X.iloc[:5]
    batched = explain.explain_matches(explainer, rows)
    assert len(batched) == 5
    for i, contributions in enumerate(batched):
        assert contributions == pytest.approx(explain.explain_match(explainer, X.iloc[[i]]))


def test_explain_matches_on_empty_frame_returns_empty():
    rf = RandomForestClassifier(n_estimators=10).fit(X, y)
    explainer = explain.make_explainer("random_forest", rf, X)
    assert explain.explain_matches(explainer, X.iloc[:0]) == []
