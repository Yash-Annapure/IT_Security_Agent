import shap


def make_explainer(model_name: str, model, background):
    if model_name == "logistic_regression":
        return shap.LinearExplainer(model, background)
    if model_name == "random_forest":
        return shap.TreeExplainer(model)
    raise ValueError(f"no SHAP explainer wired up for {model_name}")


def _positive_class(shap_values):
    """Slice to the "real match" class. TreeExplainer returns (n_samples, n_features,
    n_classes); older versions and LinearExplainer return a per-class list or a 2D array."""
    if isinstance(shap_values, list):
        return shap_values[1]
    if getattr(shap_values, "ndim", 2) == 3:
        return shap_values[:, :, 1]
    return shap_values


def explain_match(explainer, row) -> dict:
    return explain_matches(explainer, row)[0]


def explain_matches(explainer, rows) -> list:
    """SHAP contributions for a DataFrame of candidates in one explainer call."""
    if len(rows) == 0:
        return []
    values = _positive_class(explainer.shap_values(rows))
    return [dict(zip(rows.columns, [float(v) for v in row])) for row in values]
