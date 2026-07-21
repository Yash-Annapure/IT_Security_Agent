import json
from pathlib import Path

import pandas as pd


def _finding_to_dict(f):
    return {
        "package": f.component.name, "version": f.component.version, "ecosystem": f.component.ecosystem,
        "cve": f.cve, "severity": f.severity, "cvss_score": f.cvss_score,
        "confidence": f.confidence, "corroboration": f.corroboration, "kev_hit": f.kev_hit,
        "model_confident": f.model_confident, "note": f.note, "explanation": f.explanation,
        # What the vulnerability actually is - carried through from the NVD record so
        # consumers of the JSON/HTML report don't have to re-query NVD to explain it.
        "description": getattr(f, "description", ""),
        "cwe_ids": getattr(f, "cwe_ids", []),
        "vendor": getattr(f, "vendor", ""),
    }


OSV_ECOSYSTEMS = {"PyPI", "npm"}


def osv_agreement_summary(result) -> dict:
    # Only measure OSV agreement over findings the model was independently confident
    # about. Low-confidence-but-OSV-agrees confirmations can't disagree by construction
    # (OSV itself pushed them into `confirmed`), so including them would make this an
    # inflated, partly circular "independent agreement" rate.
    eligible = [
        f for f in result.confirmed
        if f.component.ecosystem in OSV_ECOSYSTEMS and f.model_confident
    ]
    agreed = [f for f in eligible if f.corroboration == "osv_agrees"]
    rate = (len(agreed) / len(eligible)) if eligible else None
    return {"eligible": len(eligible), "agreed": len(agreed), "agreement_rate": rate}


def to_dict(result) -> dict:
    return {
        "confirmed": [_finding_to_dict(f) for f in result.confirmed],
        "escalated": [_finding_to_dict(f) for f in result.escalated],
        "review_queue": [_finding_to_dict(f) for f in result.review_queue],
        "rejected": [_finding_to_dict(f) for f in result.rejected],
        "osv_agreement_summary": osv_agreement_summary(result),
    }


def to_json(result, out_path: Path) -> dict:
    payload = to_dict(result)
    Path(out_path).write_text(json.dumps(payload, indent=2))
    return payload


def _table_html(findings, title):
    if not findings:
        return f"<h3>{title}</h3><p>None</p>"
    df = pd.DataFrame([_finding_to_dict(f) for f in findings])
    return f"<h3>{title}</h3>" + df.to_html(index=False)


def to_html(result, out_path: Path) -> str:
    summary = osv_agreement_summary(result)
    rate_text = f"{summary['agreement_rate']:.0%}" if summary["agreement_rate"] is not None else "n/a"
    sections = [
        f"<h3>OSV agreement (PyPI/npm confirmed findings)</h3>"
        f"<p>{summary['agreed']}/{summary['eligible']} corroborated ({rate_text})</p>",
        _table_html(result.escalated, "Escalated (KEV-confirmed exploitation)"),
        _table_html(result.confirmed, "Confirmed findings"),
        _table_html(result.review_queue, "Human review queue"),
        "<details><summary>Rejected candidates</summary>" + _table_html(result.rejected, "Rejected") + "</details>",
    ]
    html = "<html><body>" + "\n".join(sections) + "</body></html>"
    Path(out_path).write_text(html)
    return html


def write_report(result, out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    to_json(result, out_dir / "findings.json")
    to_html(result, out_dir / "report.html")
