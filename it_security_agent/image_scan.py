import json
import subprocess

from it_security_agent.sbom import parse_cyclonedx


class ImageScanError(RuntimeError):
    pass


def scan_image(image_ref: str, run_fn=subprocess.run):
    try:
        result = run_fn(
            ["syft", image_ref, "-o", "cyclonedx-json"],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError as exc:
        raise ImageScanError("syft CLI not found - install it before scanning images") from exc
    if result.returncode != 0:
        raise ImageScanError(f"syft failed for {image_ref}: {result.stderr.strip()}")
    data = json.loads(result.stdout)
    return parse_cyclonedx(data, source_label=f"container image ({image_ref})")
