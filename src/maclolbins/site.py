"""Render a scan result as a browsable Apple-LOLBin report.

The page is `browser.html`, a self-contained column browser over the scanned filesystem. It
reads `window.LOLBINS` from `assets/data.js`, which this module writes.  The probe keeps a broad
executable inventory so the catalogue can be audited, but the user-facing report contains only
usable catalogue paths that the scan identifies as part of the Apple-protected macOS install.
"""

import json
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

from maclolbins.entitlements import RUNTIME_WEAKENERS, explain
from maclolbins.probe import TccGrant
from maclolbins.scan import InventoryItem, ScanResult
from maclolbins.tcc import SERVICE_LABELS

# Pages written by earlier versions of this renderer, removed when re-rendering over them.
_STALE = ("catalog.html", "inventory.html", "entitlements.html", "report.html")
_STALE_DIRS = ("binaries", "files")


def render_site(scan: ScanResult, out_dir: Path) -> Path:
    """Write the report into out_dir and return the path of its index page.

    Args:
        scan: The scan to render.
        out_dir: Directory to write into; existing report files are replaced.

    Returns:
        The path of index.html.
    """
    index = out_dir / "index.html"
    index.write_text(
        resources.files("maclolbins").joinpath("browser.html").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assets = out_dir / "assets"
    assets.mkdir(exist_ok=True)
    payload = json.dumps(site_data(scan), separators=(",", ":"), sort_keys=False)
    (assets / "data.js").write_text(f"window.LOLBINS = {payload};\n", encoding="utf-8")

    for name in _STALE:
        (out_dir / name).unlink(missing_ok=True)
    for name in _STALE_DIRS:
        shutil.rmtree(out_dir / name, ignore_errors=True)
    for name in ("site.css", "site.js"):
        (assets / name).unlink(missing_ok=True)
    return index


def site_data(scan: ScanResult) -> dict[str, Any]:
    """Return everything the page needs, as the `window.LOLBINS` object."""
    inventory = [item for item in scan["inventory"] if _is_usable_apple_lolbin(item)]
    return {
        "facts": scan["facts"],
        "scan_dirs": scan["scan_dirs"],
        "catalog_version": scan["catalog_version"],
        "tool_version": scan["tool_version"],
        "entries": scan["entries"],
        "inventory": [_file(item) for item in inventory],
        "entitlements": _explanations(inventory),
        "tcc": _visible_tcc(scan, inventory),
        "tcc_labels": SERVICE_LABELS,
        "runtime_weakeners": RUNTIME_WEAKENERS,
    }


def _is_usable_apple_lolbin(item: InventoryItem) -> bool:
    """Whether an inventory item belongs in the focused, user-facing report.

    Catalogue membership supplies the project's LOLBin decision.  A platform signature or SIP's
    ``restricted`` flag supplies evidence that the path belongs to the stock Apple install; the
    latter deliberately retains Apple system scripts, which are commonly unsigned.  Inactive
    xcode-select shims are not usable binaries and therefore do not count as present LOLBins.
    """
    record = item["file"]
    return bool(
        item["catalog_entry"]
        and not record["is_dev_shim"]
        and (record["signing"]["platform_binary"] or "restricted" in record["bsd_flags"])
    )


def _visible_tcc(scan: ScanResult, inventory: list[InventoryItem]) -> dict[str, Any]:
    """Keep TCC collection status plus grants that matched a visible Apple LOLBin."""
    grants: list[TccGrant] = []
    seen: set[str] = set()
    for item in inventory:
        for grant in item["tcc"]:
            key = json.dumps(grant, sort_keys=True)
            if key not in seen:
                seen.add(key)
                grants.append(grant)
    return {"sources": scan["tcc"]["sources"], "grants": grants}


def _file(item: InventoryItem) -> dict[str, Any]:
    """Flatten one inventory item; entitlement values stay exactly as the scan recorded them."""
    record = item["file"]
    return {
        "path": record["path"],
        "summary": record["summary"],
        "link": record["link_target"],
        "owner": f"{record['owner']}:{record['group']}",
        "perms": record["perms"],
        "size": record["size"],
        "sha256": record["sha256"],
        "bsd_flags": record["bsd_flags"],
        "signing": record["signing"],
        "entitlements": record["entitlements"],
        "xpc": record["xpc"],
        "flags": item["flags"],
        "tcc": item["tcc"],
        "entry": item["catalog_entry"],
    }


def _explanations(inventory: list[InventoryItem]) -> dict[str, dict[str, Any]]:
    """Explain every entitlement key held by any inventoried file, keyed by the key itself."""
    keys = {key for item in inventory for key in item["file"]["entitlements"]}
    out = {}
    for key in sorted(keys):
        info = explain(key)
        out[key] = {
            "title": info.title,
            "summary": info.summary,
            "namespace": info.namespace,
            "url": info.url,
            "documented": info.documented,
        }
    return out
