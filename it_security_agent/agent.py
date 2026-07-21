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
    # Carried through from matching.find_candidates so reports can explain what the
    # vulnerability actually *is*, not just cite its ID. matching already extracts
    # both from the NVD record; dropping them here would mean re-querying to report.
    description: str = ""
    cwe_ids: list = field(default_factory=list)
    vendor: str = ""


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


def triage_component(component, winning_model_name, winning_model, threshold, explainer, conn=None,
                     kev_ids=None):
    """Triage one component's candidate matches into the four buckets.

    `kev_ids` is an optional preloaded set (kev.load_kev_ids) so a whole scan does one
    KEV read; omit it to triage a component standalone and pay per-CVE lookups.
    """
    result = ScanResult()
    matches, rejected_ids = matching.find_candidates(component, conn=conn)

    for cve_id in rejected_ids:
        result.rejected.append(Finding(component=component, cve=cve_id, severity="UNKNOWN", cvss_score=None))

    scored = []
    for finding_data in matches:
        candidate = finding_data.get("vendor_candidate")
        if candidate is None:
            result.rejected.append(Finding(
                component=component, cve=finding_data["cve"], severity=finding_data["severity"],
                cvss_score=finding_data["cvss_score"],
                description=finding_data.get("description", ""),
                cwe_ids=finding_data.get("cwe_ids", []), vendor=finding_data.get("vendor", ""),
            ))
            continue
        scored.append((finding_data, candidate))

    if not scored:
        return result

    # OSV is keyed on the component, not the match, so one query answers every candidate
    # CVE here - per-finding it was a network round trip per candidate on a cache miss.
    osv_vulns = (
        osv.query(component.ecosystem, component.name, component.version, conn=conn)
        if component.ecosystem in OSV_ECOSYSTEMS else []
    )
    # Always computed, for every PyPI/npm finding, regardless of confidence -
    # report.py's OSV agreement rate (the evaluation-oracle metric) aggregates
    # over confirmed findings, so a corroboration value that's only checked
    # sometimes would silently corrupt that statistic.
    corroboration = _corroboration(component, osv_vulns)

    # Reconcile the scan-time feature vector with labeling.FEATURES (what the model was
    # actually trained on): drop registry_overlap, add ecosystem_pypi and osv_corroborated.
    feature_rows = [
        {
            **candidate.signals,
            "ecosystem_pypi": int(component.ecosystem == "PyPI"),
            "osv_corroborated": int(len(osv_vulns) > 0),
        }
        for _, candidate in scored
    ]
    confidences = model.predict_confidence_batch(winning_model, feature_rows)

    needs_explaining = []
    for (finding_data, _), feature_signals, confidence in zip(scored, feature_rows, confidences):
        cve_id = finding_data["cve"]
        kev_hit = cve_id in kev_ids if kev_ids is not None else bool(kev.is_kev(cve_id, conn=conn))
        model_confident = confidence is not None and confidence >= threshold
        f = Finding(
            component=component, cve=cve_id, severity=finding_data["severity"],
            cvss_score=finding_data["cvss_score"], confidence=confidence, kev_hit=kev_hit,
            corroboration=corroboration, model_confident=model_confident,
            description=finding_data.get("description", ""),
            cwe_ids=finding_data.get("cwe_ids", []), vendor=finding_data.get("vendor", ""),
        )

        trusted = finding_data.get("registry_trusted_vendors") or frozenset()
        vendor_conflict = bool(trusted) and finding_data.get("vendor") not in trusted
        model_says_yes = confidence >= threshold or corroboration == "osv_agrees"

        if model_says_yes and (kev_hit or not vendor_conflict):
            # A KEV hit is exempt from the vendor gate on purpose: with a missed
            # vulnerability weighted 10x a false alarm, an actively-exploited CVE belongs
            # in front of a human even when the vendor looks wrong.
            (result.escalated if kev_hit else result.confirmed).append(f)
        else:
            if vendor_conflict and model_says_yes:
                f.note = (f"matched NVD vendor `{finding_data.get('vendor')}`, but this package's "
                          f"registry page identifies its vendor as "
                          f"{' or '.join(f'`{v}`' for v in sorted(trusted))} - likely a name collision")
            else:
                f.note = ("not corroborated by OSV" if corroboration == "osv_disagrees"
                          else "OSV not applicable to this ecosystem")
            result.review_queue.append(f)
            needs_explaining.append((f, feature_signals))

    if needs_explaining:
        explain_rows = pd.DataFrame(
            [{feat: signals.get(feat, 0) for feat in labeling.FEATURES} for _, signals in needs_explaining]
        )
        for (f, _), contributions in zip(needs_explaining, explain.explain_matches(explainer, explain_rows)):
            f.explanation = contributions

    return result


def scan(components, winning_model_name, winning_model, threshold, explainer, conn=None) -> ScanResult:
    total = ScanResult()
    kev_ids = kev.load_kev_ids(conn=conn)
    for component in components:
        partial = triage_component(component, winning_model_name, winning_model, threshold, explainer,
                                   conn=conn, kev_ids=kev_ids)
        total.confirmed += partial.confirmed
        total.escalated += partial.escalated
        total.review_queue += partial.review_queue
        total.rejected += partial.rejected
    return total
