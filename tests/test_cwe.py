from it_security_agent import cwe


def test_technical_name_resolves_known_ids():
    assert cwe.technical_name("CWE-79") == "Cross-site Scripting (XSS)"
    assert cwe.technical_name("CWE-89") == "SQL Injection"


def test_plain_explanation_is_written_for_non_specialists():
    explanation = cwe.plain_explanation("CWE-89")
    assert "database" in explanation
    assert "CWE" not in explanation  # no jargon echoed back at the reader


def test_lookup_is_case_and_whitespace_tolerant():
    assert cwe.technical_name(" cwe-79 ") == "Cross-site Scripting (XSS)"
    assert cwe.plain_explanation("cwe-79") is not None


def test_unmapped_ids_degrade_to_the_bare_id_rather_than_failing():
    # An unmapped CWE must never break a report - it just loses the plain-English line.
    assert cwe.technical_name("CWE-99999") == "CWE-99999"
    assert cwe.plain_explanation("CWE-99999") is None
    assert cwe.url("CWE-99999") == "https://cwe.mitre.org/data/definitions/99999.html"


def test_url_returns_none_for_malformed_ids():
    assert cwe.url("NOT-A-CWE") is None


def test_unmapped_cwe_is_not_printed_twice_in_a_report():
    # technical_name() falls back to the bare ID, so a naive "<id> <name>" label would
    # render "CWE-99999 CWE-99999". Guard the contract the report formatter relies on.
    unmapped = "CWE-99999"
    assert cwe.technical_name(unmapped) == unmapped


def test_every_entry_has_both_a_name_and_a_plain_explanation():
    for cwe_id, entry in cwe.NAMES.items():
        assert cwe_id.startswith("CWE-"), cwe_id
        name, plain = entry
        assert name and plain, cwe_id
        assert not plain.endswith("."), f"{cwe_id}: explanations are clause fragments, joined by the caller"
