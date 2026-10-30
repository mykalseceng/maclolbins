"""Combine probe output with the catalog into a scan result, and save/load it as JSON."""

import json
from importlib.metadata import version
from pathlib import Path
from typing import Literal, TypedDict

from lolbins.catalog import Catalog, Entry
from lolbins.entitlements import runtime_weakeners
from lolbins.probe import FileRecord, ProbeOutput, TccGrant, TccSnapshot

SCHEMA_VERSION = 5
DEFAULT_SCAN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec")

PathStatus = Literal["present", "inactive-shim", "missing"]
TCC_ENTITLEMENT = "com.apple.private.tcc."


class PathFinding(TypedDict):
    """Whether one catalogued path exists on the target."""

    path: str
    status: PathStatus


class TechniqueRef(TypedDict):
    """An ATT&CK technique ID with its name, copied in so reports need no catalog."""

    id: str
    name: str


class ExampleRef(TypedDict):
    """A worked command copied from the catalog, so reports need no catalog."""

    title: str
    command: str
    explanation: str
    privilege: str


class EntryFinding(TypedDict):
    """A catalog entry and its presence on the target (best status across its paths)."""

    name: str
    status: PathStatus
    tactics: list[str]
    techniques: list[TechniqueRef]
    privilege: str
    abuse: str
    xpc_functionality: str | None
    description: str | None
    examples: list[ExampleRef]
    paths: list[PathFinding]


class InventoryItem(TypedDict):
    """One probed file with its attention flags and the TCC grants naming it."""

    file: FileRecord
    catalog_entry: str | None
    flags: list[str]
    tcc: list[TccGrant]


class ScanResult(TypedDict):
    """A complete scan; this is the scan.json schema."""

    schema: int
    tool_version: str
    catalog_version: str
    target: str
    scan_dirs: list[str]
    facts: dict[str, str]
    tcc: TccSnapshot
    entries: list[EntryFinding]
    inventory: list[InventoryItem]


class ScanFileError(ValueError):
    """A saved scan file cannot be read."""


def build_scan(
    catalog: Catalog, probe: ProbeOutput, target: str, scan_dirs: list[str]
) -> ScanResult:
    """Match probe output against the catalog and annotate every inventoried file."""
    shims_active = probe["facts"].get("developer_dir", "none") != "none"
    owner_by_path = {path: entry.name for entry in catalog.entries for path in entry.paths}
    entries = [_entry_finding(catalog, entry, probe, shims_active) for entry in catalog.entries]
    inventory = [
        _inventory_item(record, owner_by_path.get(path), probe["tcc"]["grants"])
        for path, record in sorted(probe["files"].items())
    ]
    return ScanResult(
        schema=SCHEMA_VERSION,
        tool_version=version("lolbins"),
        catalog_version=catalog.version,
        target=target,
        scan_dirs=scan_dirs,
        facts=probe["facts"],
        tcc=probe["tcc"],
        entries=entries,
        inventory=inventory,
    )


def rejoin_catalog(scan: ScanResult, catalog: Catalog) -> ScanResult:
    """Return the scan with its catalog-derived parts rebuilt from `catalog`.

    The probe records what is on the host; the catalog records what each binary is good for.
    Re-joining them at render time means catalog edits (new examples, reworded abuse) reach a
    report without re-running the scan.

    Args:
        scan: A scan loaded from disk.
        catalog: The catalog to join against.

    Returns:
        A new scan result; the probe's own findings are unchanged.
    """
    probe = ProbeOutput(
        facts=scan["facts"],
        files={item["file"]["path"]: item["file"] for item in scan["inventory"]},
        missing=[],
        tcc=scan["tcc"],
    )
    rebuilt = build_scan(catalog, probe, target=scan["target"], scan_dirs=scan["scan_dirs"])
    rebuilt["tool_version"] = scan["tool_version"]
    return rebuilt


def file_flags(record: FileRecord) -> list[str]:
    """Return short labels for properties of a file that deserve attention."""
    perms = record["perms"] or ""
    stat_ok = record["perms"] is not None
    signing = record["signing"]
    checks = [
        ("setuid", len(perms) > 3 and perms[3] in "sS"),
        ("setgid", len(perms) > 6 and perms[6] in "sS"),
        ("world-writable", len(perms) > 8 and perms[8] == "w"),
        ("dev-shim", record["is_dev_shim"]),
        ("script", record["is_script"]),
        ("unsigned", signing["state"] == "unsigned" and not record["is_script"]),
        ("adhoc-signed", signing["state"] == "adhoc"),
        ("unreadable", signing["state"] == "unreadable"),
        # Apple's own binaries carry no TeamIdentifier; Developer ID and App Store code does.
        ("third-party", signing["state"] == "signed" and signing["team_id"] is not None),
        # SIP marks the files it protects with the restricted flag; no stat means no verdict.
        ("sip-unprotected", stat_ok and "restricted" not in record["bsd_flags"]),
        ("weakened-runtime", bool(runtime_weakeners(record["entitlements"]))),
        ("tcc-entitled", any(key.startswith(TCC_ENTITLEMENT) for key in record["entitlements"])),
        ("xpc-server-candidate", bool(record["xpc"])),
    ]
    return [label for label, applies in checks if applies]


def tcc_grants_for(record: FileRecord, grants: list[TccGrant]) -> list[TccGrant]:
    """Return the TCC grants whose client is this file, by path or by signing identifier."""
    identifier = record["signing"]["identifier"]
    return [
        grant
        for grant in grants
        if (grant["client_type"] == "path" and grant["client"] == record["path"])
        or (grant["client_type"] == "bundle" and identifier and grant["client"] == identifier)
    ]


def save_scan(scan: ScanResult, path: Path) -> None:
    """Write a scan result as indented JSON."""
    path.write_text(json.dumps(scan, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def load_scan(path: Path) -> ScanResult:
    """Read a scan result written by save_scan.

    Raises:
        ScanFileError: If the file is unreadable, not JSON, or from another schema version.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanFileError(f"cannot read scan file {path}: {exc}") from exc
    if isinstance(data, dict) and data.get("schema") == 4:
        for item in data.get("inventory", []):
            if isinstance(item, dict) and isinstance(item.get("file"), dict):
                item["file"].setdefault("xpc", [])
        data["schema"] = SCHEMA_VERSION
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        found = data.get("schema") if isinstance(data, dict) else type(data).__name__
        raise ScanFileError(
            f"{path}: expected scan schema {SCHEMA_VERSION}, found {found!r}; re-run the scan"
        )
    scan: ScanResult = data
    return scan


def _path_status(path: str, probe: ProbeOutput, shims_active: bool) -> PathStatus:
    record = probe["files"].get(path)
    if record is None:
        return "missing"
    if record["is_dev_shim"] and not shims_active:
        return "inactive-shim"
    return "present"


def _entry_finding(
    catalog: Catalog, entry: Entry, probe: ProbeOutput, shims_active: bool
) -> EntryFinding:
    paths = [
        PathFinding(path=path, status=_path_status(path, probe, shims_active))
        for path in entry.paths
    ]
    statuses = {finding["status"] for finding in paths}
    status: PathStatus = next(s for s in ("present", "inactive-shim", "missing") if s in statuses)
    summaries = (probe["files"][p].get("summary") for p in entry.paths if p in probe["files"])
    return EntryFinding(
        name=entry.name,
        status=status,
        tactics=catalog.tactics_for(entry),
        techniques=[TechniqueRef(id=t, name=catalog.techniques[t].name) for t in entry.techniques],
        privilege=entry.privilege,
        abuse=entry.abuse,
        xpc_functionality=entry.xpc_functionality,
        description=next((s for s in summaries if s), None),
        examples=[
            ExampleRef(
                title=example.title,
                command=example.command,
                explanation=example.explanation,
                privilege=example.privilege,
            )
            for example in entry.examples
        ],
        paths=paths,
    )


def _inventory_item(
    record: FileRecord, catalog_entry: str | None, grants: list[TccGrant]
) -> InventoryItem:
    matched = tcc_grants_for(record, grants)
    flags = file_flags(record)
    if any(grant["auth"] == "allowed" for grant in matched):
        flags.append("tcc-granted")
    return InventoryItem(file=record, catalog_entry=catalog_entry, flags=flags, tcc=matched)
