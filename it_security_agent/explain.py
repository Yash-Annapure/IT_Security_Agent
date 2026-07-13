import shap


def make_explainer(model_name: str, model, background):
    if model_name == "logistic_regression":
        return shap.LinearExplainer(model, background)
    if model_name == "random_forest":
        return shap.TreeExplainer(model)
    raise ValueError(f"no SHAP explainer wired up for {model_name}")


def explain_match(explainer, row) -> dict:
    shap_values = explainer.shap_values(row)
    if isinstance(shap_values, list):
        values = shap_values[1][0]
    elif getattr(shap_values, "ndim", 1) == 3:
        values = shap_values[0, :, 1]
    else:
        values = shap_values[0]
    return dict(zip(row.columns, [float(v) for v in values]))
