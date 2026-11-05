"""`oss-pulse scan`: read an untrusted folder before you open or install it. No network.

The folder is untrusted, so nothing inside it configures the scan: an ignore file only
applies when the user passes it with `--ignore-file`.
"""

from oss_pulse.scan.pipeline import IGNORE_FILE, ScanResult, run_scan
from oss_pulse.scan.report import render_scan_json, render_scan_markdown

__all__ = ["IGNORE_FILE", "ScanResult", "render_scan_json", "render_scan_markdown", "run_scan"]
