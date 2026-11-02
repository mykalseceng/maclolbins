"""Render a scan result as a browsable Apple-LOLBin report.

The page is `browser.html`, a self-contained column browser over the scanned filesystem. It
reads `window.LOLBINS` from `assets/data.js`, which this module writes. The probe inventories
every executable on the target's default PATH; the report keeps the Apple ones, ranked by how
much capability and privilege evidence each carries.
"""

import json
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

from maclolbins.entitlements import RUNTIME_WEAKENERS, explain
from maclolbins.probe import FileRecord, TccGrant
from maclolbins.scan import InventoryItem, NoteRef, ScanResult, TechniqueRef
from maclolbins.tcc import SERVICE_LABELS

# Flags that say a binary runs with, or can reach, more than its caller could. Each counts
# twice a capability in the evidence score.
PRIVILEGE_SIGNALS = (
    "setuid",
    "setgid",
    "private-entitled",
    "tcc-entitled",
    "tcc-granted",
    "weakened-runtime",
    "xpc-server-candidate",
)
SIGNAL_WEIGHT = 2

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
    inventory = [item for item in scan["inventory"] if in_report(item)]
    notes = {note["name"]: note for note in scan["notes"]}
    capabilities = {cap["id"]: cap for cap in scan["capabilities"]}
    return {
        "facts": scan["facts"],
        "scan_dirs": scan["scan_dirs"],
        "catalog_version": scan["catalog_version"],
        "tool_version": scan["tool_version"],
        "inventoried": len(scan["inventory"]),
        "capabilities": capabilities,
        "notes": notes,
        "inventory": [_file(item, capabilities, notes) for item in inventory],
        "entitlements": _explanations(inventory),
        "tcc": _visible_tcc(scan, inventory),
        "tcc_labels": SERVICE_LABELS,
        "runtime_weakeners": RUNTIME_WEAKENERS,
    }


def in_report(item: InventoryItem) -> bool:
    """Whether an inventoried file belongs in the report.

    It must be part of the stock Apple install, shown by a platform signature or by SIP's
    restricted flag (which keeps Apple's unsigned system scripts), and not an inactive
    xcode-select shim. Evidence does not decide inclusion: a binary whose abuse is its normal
    job (id, base64) imports nothing distinctive, so it is listed with a score of 0.
    """
    record = item["file"]
    apple = record["signing"]["platform_binary"] or "restricted" in record["bsd_flags"]
    return bool(apple and not record["is_dev_shim"])


def evidence_score(item: InventoryItem) -> int:
    """Return one point per capability plus SIGNAL_WEIGHT per privilege signal."""
    signals = set(PRIVILEGE_SIGNALS) & set(item["flags"])
    return len(item["capabilities"]) + SIGNAL_WEIGHT * len(signals)


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


def _file(
    item: InventoryItem, capabilities: dict[str, Any], notes: dict[str, NoteRef]
) -> dict[str, Any]:
    """Flatten one inventory item; entitlement values stay exactly as the scan recorded them.

    Techniques and tactics combine the file's capabilities with its note, if it has one.
    """
    record = item["file"]
    note = notes.get(item["note"]) if item["note"] else None
    techniques: dict[str, TechniqueRef] = {}
    tactics: dict[str, None] = {}
    for source in [capabilities[match["id"]] for match in item["capabilities"]] + (
        [note] if note else []
    ):
        techniques.update({t["id"]: t for t in source["techniques"]})
        tactics.update(dict.fromkeys(source["tactics"]))
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
        "capabilities": item["capabilities"],
        "libraries": record["libraries"],
        "note": item["note"],
        "techniques": list(techniques.values()),
        "tactics": list(tactics),
        "privilege": note["privilege"] if note else _privilege(record),
        "score": evidence_score(item),
    }


def _privilege(record: FileRecord) -> str:
    """Who can run the file: "user" when others may execute it, else "root"."""
    perms = record["perms"] or ""
    return "user" if len(perms) > 9 and perms[9] in "xst" else "root"


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
