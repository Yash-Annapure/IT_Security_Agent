from unittest.mock import MagicMock

from it_security_agent import kev, nvd_cache


def _response(entries):
    resp = MagicMock()
    resp.json.return_value = {"vulnerabilities": entries}
    resp.raise_for_status = MagicMock()
    return resp


def test_refresh_stores_entries():
    conn = nvd_cache.get_connection(":memory:")
    entries = [{"cveID": "CVE-2024-0001", "dueDate": "2024-02-01"}]
    get_fn = MagicMock(return_value=_response(entries))
    count = kev.refresh(conn=conn, get_fn=get_fn)
    assert count == 1


def test_is_kev_returns_entry_when_present():
    conn = nvd_cache.get_connection(":memory:")
    entries = [{"cveID": "CVE-2024-0001", "dueDate": "2024-02-01"}]
    kev.refresh(conn=conn, get_fn=MagicMock(return_value=_response(entries)))
    result = kev.is_kev("CVE-2024-0001", conn=conn)
    assert result["dueDate"] == "2024-02-01"


def test_is_kev_returns_none_when_absent():
    conn = nvd_cache.get_connection(":memory:")
    kev.refresh(conn=conn, get_fn=MagicMock(return_value=_response([])))
    assert kev.is_kev("CVE-9999-9999", conn=conn) is None
