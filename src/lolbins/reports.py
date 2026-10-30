"""Keep each scan in its own report directory, and find it again by its scan ID.

A report directory holds scan.json plus the rendered report (index.html and assets/data.js).
Its name, `<target>-<collected_at>`, is the scan ID that the MCP server hands out and accepts.
"""

import re
from pathlib import Path

from lolbins.scan import ScanFileError, ScanResult, save_scan
from lolbins.site import render_site

SCAN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def write_report(scan: ScanResult, reports_dir: Path) -> Path:
    """Save the scan and render its report into a new directory under reports_dir.

    Args:
        scan: The scan to keep.
        reports_dir: Parent directory; created if missing.

    Returns:
        The new report directory, whose name is the scan ID.

    Raises:
        FileExistsError: If a scan of the same target collected at the same second exists.
    """
    stamp = scan["facts"].get("collected_at", "unknown").replace(":", "").replace("-", "")
    out_dir = reports_dir / f"{safe_name(scan['target'])}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=False)
    save_scan(scan, out_dir / "scan.json")
    render_site(scan, out_dir)
    return out_dir


def scan_ids(reports_dir: Path) -> list[str]:
    """Return the IDs of every saved scan under reports_dir, oldest name first."""
    if not reports_dir.is_dir():
        return []
    return sorted(
        child.name
        for child in reports_dir.iterdir()
        if SCAN_ID.fullmatch(child.name) and (child / "scan.json").is_file()
    )


def scan_path(reports_dir: Path, scan_id: str) -> Path:
    """Return the scan.json for a scan ID.

    Raises:
        ScanFileError: If the ID is malformed or no such scan exists.
    """
    if not SCAN_ID.fullmatch(scan_id):
        raise ScanFileError(
            f"{scan_id!r} is not a scan ID; scan IDs look like macOS-20261026T215409Z"
        )
    path = reports_dir / scan_id / "scan.json"
    if not path.is_file():
        raise ScanFileError(
            f"no scan {scan_id!r} in {reports_dir}; list_scans shows the saved ones"
        )
    return path


def safe_name(name: str) -> str:
    """Make a directory-name prefix that starts with a letter or digit and holds no separators."""
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in name).lstrip("-_.")
    return cleaned or "target"
