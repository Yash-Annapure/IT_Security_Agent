from dataclasses import dataclass, field

import pandas as pd

from it_security_agent import explain, kev, labeling, matching, model, osv

OSV_ECOSYSTEMS = {"PyPI", "npm"}


@dataclass
class Finding:
    component: object
    cve: str
    severity: str
    cvss_score: float
    confidence: float | None = None
    corroboration: str = "not_checked"
    explanation: dict | None = None
    kev_hit: bool = False
    note: str = ""
    model_confident: bool = False


@dataclass
class ScanResult:
    confirmed: list = field(default_factory=list)
    escalated: list = field(default_factory=list)
    review_queue: list = field(default_factory=list)
    rejected: list = field(default_factory=list)


def _corroboration(component, osv_vulns):
    # Loose match by design: OSV doesn't always populate CVE aliases cleanly, so
    # requiring an exact CVE-ID match here would systematically undercount real
    # agreement. "OSV found anything for this exact (ecosystem, name, version)"
    # is the practical bar - independent evidence a vulnerability exists here at all.
    # Takes the already-fetched OSV result list so we never query OSV twice per finding.
    if component.ecosystem not in OSV_ECOSYSTEMS:
        return "not_checked"
    return "osv_agrees" if osv_vulns else "osv_disagrees"


def triage_component(component, winning_model_name, winning_model, threshold, explainer, conn=None):
    result = ScanResult()
    matches, rejected_ids = matching.find_candidates(component, conn=conn)

    for cve_id in rejected_ids:
        result.rejected.append(Finding(component=component, cve=cve_id, severity="UNKNOWN", cvss_score=None))

    for finding_data in matches:
        candidate = finding_data.get("vendor_candidate")
        kev_entry = kev.is_kev(finding_data["cve"], conn=conn)

        if candidate is None:
            result.rejected.append(Finding(
                component=component, cve=finding_data["cve"], severity=finding_data["severity"],
                cvss_score=finding_data["cvss_score"],
            ))
            continue

        # Reconcile the scan-time feature vector with labeling.FEATURES (what the
        # model was actually trained on): drop registry_overlap, add ecosystem_pypi
        # and osv_corroborated. The OSV query is done once here and reused for both
        # the osv_corroborated feature and the corroboration label below.
        osv_vulns = (
            osv.query(component.ecosystem, component.name, component.version, conn=conn)
            if component.ecosystem in OSV_ECOSYSTEMS else []
        )
        feature_signals = {
            **candidate.signals,
            "ecosystem_pypi": int(component.ecosystem == "PyPI"),
            "osv_corroborated": int(len(osv_vulns) > 0),
        }
        confidence = model.predict_confidence(winning_model, feature_signals)
        # Always computed, for every PyPI/npm finding, regardless of confidence -
        # report.py's OSV agreement rate (the evaluation-oracle metric) aggregates
        # over confirmed findings, so a corroboration value that's only checked
        # sometimes would silently corrupt that statistic.
        corroboration = _corroboration(component, osv_vulns)
        model_confident = confidence is not None and confidence >= threshold
        f = Finding(
            component=component, cve=finding_data["cve"], severity=finding_data["severity"],
            cvss_score=finding_data["cvss_score"], confidence=confidence, kev_hit=bool(kev_entry),
            corroboration=corroboration, model_confident=model_confident,
        )

        if confidence >= threshold or corroboration == "osv_agrees":
            (result.escalated if kev_entry else result.confirmed).append(f)
        else:
            explain_row = pd.DataFrame([{feat: feature_signals.get(feat, 0) for feat in labeling.FEATURES}])
            f.explanation = explain.explain_match(explainer, explain_row)
            f.note = "not corroborated by OSV" if corroboration == "osv_disagrees" else "OSV not applicable to this ecosystem"
            result.review_queue.append(f)

    return result


def scan(components, winning_model_name, winning_model, threshold, explainer, conn=None) -> ScanResult:
    total = ScanResult()
    for component in components:
        partial = triage_component(component, winning_model_name, winning_model, threshold, explainer, conn=conn)
        total.confirmed += partial.confirmed
        total.escalated += partial.escalated
        total.review_queue += partial.review_queue
        total.rejected += partial.rejected
    return total
