import json
from pathlib import Path

from it_security_agent import report
from it_security_agent.agent import Finding, ScanResult
from it_security_agent.schema import Component


def _finding(cve="CVE-2024-0001"):
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    return Finding(component=component, cve=cve, severity="HIGH", cvss_score=7.5)



def test_to_dict_has_all_four_buckets_plus_osv_summary():
    result = ScanResult(confirmed=[_finding()], rejected=[_finding("CVE-2024-0002")])
    payload = report.to_dict(result)
    assert set(payload.keys()) == {"confirmed", "escalated", "review_queue", "rejected", "osv_agreement_summary"}
    assert len(payload["confirmed"]) == 1
    assert len(payload["rejected"]) == 1


def test_osv_agreement_summary_counts_pypi_npm_confirmed_only():
    pypi_component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    debian_component = Component(name="openssl", version="3.0.2", ecosystem="Debian", source="test")
    agreeing = Finding(component=pypi_component, cve="CVE-2024-0001", severity="HIGH", cvss_score=7.5, corroboration="osv_agrees")
    not_checked = Finding(component=debian_component, cve="CVE-2024-0002", severity="HIGH", cvss_score=7.5, corroboration="not_checked")
    disagreeing = Finding(component=pypi_component, cve="CVE-2024-0003", severity="HIGH", cvss_score=7.5, corroboration="osv_disagrees")
    result = ScanResult(confirmed=[agreeing, not_checked, disagreeing])
    summary = report.osv_agreement_summary(result)
    assert summary["eligible"] == 2  # only the two PyPI findings count; Debian is excluded
    assert summary["agreed"] == 1
    assert summary["agreement_rate"] == 0.5


def test_to_json_writes_file(tmp_path):
    result = ScanResult(confirmed=[_finding()])
    out_path = tmp_path / "findings.json"
    report.to_json(result, out_path)
    data = json.loads(out_path.read_text())
    assert data["confirmed"][0]["cve"] == "CVE-2024-0001"


def test_to_html_includes_rejected_section_not_omitted(tmp_path):
    result = ScanResult(rejected=[_finding("CVE-2024-0003")])
    out_path = tmp_path / "report.html"
    html = report.to_html(result, out_path)
    assert "CVE-2024-0003" in html
    assert "Rejected" in html


def test_write_report_creates_both_files(tmp_path):
    result = ScanResult(confirmed=[_finding()])
    report.write_report(result, tmp_path)
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "report.html").exists()
