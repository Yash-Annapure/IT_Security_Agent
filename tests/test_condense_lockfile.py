import sys

import pytest

import condense_lockfile


def test_main_exits_with_a_clear_error_when_the_file_is_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["condense_lockfile.py", "nonexistent.lock"])
    with pytest.raises(SystemExit) as exc_info:
        condense_lockfile.main()
    assert exc_info.value.code == 1
    assert "No such file" in capsys.readouterr().err


def test_main_reads_the_given_file_and_prints_condensed_output(tmp_path, monkeypatch, capsys):
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        '[[package]]\nname = "django"\nversion = "2.2.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    monkeypatch.setattr(sys, "argv", ["condense_lockfile.py", str(lockfile)])
    condense_lockfile.main()
    assert capsys.readouterr().out.strip() == "django==2.2.0"


def test_main_defaults_to_uv_lock_in_the_current_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    monkeypatch.setattr(sys, "argv", ["condense_lockfile.py"])
    condense_lockfile.main()
    assert capsys.readouterr().out.strip() == "flask==3.0.0"
