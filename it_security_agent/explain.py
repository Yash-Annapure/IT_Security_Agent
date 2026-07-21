import shap


def make_explainer(model_name: str, model, background):
    if model_name == "logistic_regression":
        return shap.LinearExplainer(model, background)
    if model_name == "random_forest":
        return shap.TreeExplainer(model)
    raise ValueError(f"no SHAP explainer wired up for {model_name}")


def _positive_class(shap_values):
    """Slice a binary classifier's SHAP output down to the "real match" class.

    TreeExplainer returns (n_samples, n_features, n_classes); older versions and
    LinearExplainer return a list per class or a plain 2D array.
    """
    if isinstance(shap_values, list):
        return shap_values[1]
    if getattr(shap_values, "ndim", 2) == 3:
        return shap_values[:, :, 1]
    return shap_values


def explain_match(explainer, row) -> dict:
    return explain_matches(explainer, row)[0]


def explain_matches(explainer, rows) -> list:
    """SHAP contributions for a whole DataFrame of candidates, one explainer call.

    The agent explains every review-queue finding, and SHAP costs ~16ms a row either
    way - the tree walk itself dominates, not call overhead - so this mainly avoids
    re-entering the explainer once per finding.
    """
    if len(rows) == 0:
        return []
    values = _positive_class(explainer.shap_values(rows))
    return [dict(zip(rows.columns, [float(v) for v in row])) for row in values]
