import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from it_security_agent import image_scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_image_parses_syft_output():
    stdout = (FIXTURES / "sample_syft_cyclonedx.json").read_text()
    run_fn = MagicMock(return_value=MagicMock(returncode=0, stdout=stdout, stderr=""))
    components = image_scan.scan_image("python:3.11-slim", run_fn=run_fn)
    names = {c.name for c in components}
    assert names == {"openssl", "flask"}
    run_fn.assert_called_once()
    args = run_fn.call_args[0][0]
    assert args[0] == "syft"
    assert "python:3.11-slim" in args


def test_scan_image_raises_on_syft_not_found():
    run_fn = MagicMock(side_effect=FileNotFoundError())
    with pytest.raises(image_scan.ImageScanError):
        image_scan.scan_image("python:3.11-slim", run_fn=run_fn)


def test_scan_image_raises_on_nonzero_exit():
    run_fn = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="image not found"))
    with pytest.raises(image_scan.ImageScanError, match="image not found"):
        image_scan.scan_image("does-not-exist:latest", run_fn=run_fn)
