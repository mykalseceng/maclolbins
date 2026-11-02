"""Combine probe output with the catalog into a scan result, and save/load it as JSON."""

import json
from importlib.metadata import version
from pathlib import Path
from typing import TypedDict

from maclolbins.catalog import Catalog, Note
from maclolbins.entitlements import runtime_weakeners
from maclolbins.probe import FileRecord, ProbeOutput, TccGrant, TccSnapshot

SCHEMA_VERSION = 6
TCC_ENTITLEMENT = "com.apple.private.tcc."
PRIVATE_ENTITLEMENTS = ("com.apple.private.", "com.apple.rootless.")


class TechniqueRef(TypedDict):
    """An ATT&CK technique ID with its name, copied in so reports need no catalog."""

    id: str
    name: str


class CapabilityRef(TypedDict):
    """A capability rule's description, copied in so reports need no catalog."""

    id: str
    title: str
    summary: str
    techniques: list[TechniqueRef]
    tactics: list[str]


class ExampleRef(TypedDict):
    """A worked command copied from a note, so reports need no catalog."""

    title: str
    command: str
    explanation: str
    privilege: str


class NoteRef(TypedDict):
    """A hand-written note copied from the catalog, so reports need no catalog."""

    name: str
    paths: list[str]
    techniques: list[TechniqueRef]
    tactics: list[str]
    privilege: str
    abuse: str
    examples: list[ExampleRef]


class CapabilityMatch(TypedDict):
    """A capability one file shows, and the imports or libraries that show it."""

    id: str
    evidence: list[str]


class InventoryItem(TypedDict):
    """One probed file with its capabilities, attention flags and the TCC grants naming it."""

    file: FileRecord
    capabilities: list[CapabilityMatch]
    note: str | None
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
    capabilities: list[CapabilityRef]
    notes: list[NoteRef]
    inventory: list[InventoryItem]


class ScanFileError(ValueError):
    """A saved scan file cannot be read."""


def build_scan(catalog: Catalog, probe: ProbeOutput, target: str) -> ScanResult:
    """Match every inventoried file against the catalog's capability rules and notes.

    The scanned folders are the target's default PATH, which the probe reports as the
    path_dirs fact.
    """
    path_dirs = probe["facts"].get("path_dirs", "")
    inventory = [
        _inventory_item(catalog, record, probe["tcc"]["grants"])
        for _, record in sorted(probe["files"].items())
    ]
    return ScanResult(
        schema=SCHEMA_VERSION,
        tool_version=version("maclolbins"),
        catalog_version=catalog.version,
        target=target,
        scan_dirs=[d for d in path_dirs.split(":") if d],
        facts=probe["facts"],
        tcc=probe["tcc"],
        capabilities=[
            CapabilityRef(
                id=cap.id,
                title=cap.title,
                summary=cap.summary,
                techniques=_technique_refs(catalog, cap.techniques),
                tactics=catalog.tactics_for(cap.techniques),
            )
            for cap in catalog.capabilities
        ],
        notes=[_note_ref(catalog, note) for note in catalog.notes],
        inventory=inventory,
    )


def rejoin_catalog(scan: ScanResult, catalog: Catalog) -> ScanResult:
    """Return the scan with its catalog-derived parts rebuilt from `catalog`.

    The probe records what is on the host; the catalog says what that evidence means. Re-joining
    them at render time means rule and note edits reach a report without re-running the scan.

    Args:
        scan: A scan loaded from disk.
        catalog: The catalog to join against.

    Returns:
        A new scan result; the probe's own findings are unchanged.
    """
    probe = ProbeOutput(
        facts=scan["facts"],
        files={item["file"]["path"]: item["file"] for item in scan["inventory"]},
        tcc=scan["tcc"],
    )
    rebuilt = build_scan(catalog, probe, target=scan["target"])
    rebuilt["tool_version"] = scan["tool_version"]
    return rebuilt


def file_flags(record: FileRecord) -> list[str]:
    """Return short labels for properties of a file that deserve attention."""
    perms = record["perms"] or ""
    stat_ok = record["perms"] is not None
    signing = record["signing"]
    keys = record["entitlements"]
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
        ("private-entitled", any(key.startswith(PRIVATE_ENTITLEMENTS) for key in keys)),
        ("weakened-runtime", bool(runtime_weakeners(keys))),
        ("tcc-entitled", any(key.startswith(TCC_ENTITLEMENT) for key in keys)),
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
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        found = data.get("schema") if isinstance(data, dict) else type(data).__name__
        raise ScanFileError(
            f"{path}: expected scan schema {SCHEMA_VERSION}, found {found!r}; re-run the scan"
        )
    scan: ScanResult = data
    return scan


def _technique_refs(catalog: Catalog, technique_ids: tuple[str, ...]) -> list[TechniqueRef]:
    return [TechniqueRef(id=t, name=catalog.techniques[t].name) for t in technique_ids]


def _note_ref(catalog: Catalog, note: Note) -> NoteRef:
    return NoteRef(
        name=note.name,
        paths=list(note.paths),
        techniques=_technique_refs(catalog, note.techniques),
        tactics=catalog.tactics_for(note.techniques),
        privilege=note.privilege,
        abuse=note.abuse,
        examples=[
            ExampleRef(
                title=example.title,
                command=example.command,
                explanation=example.explanation,
                privilege=example.privilege,
            )
            for example in note.examples
        ],
    )


def _inventory_item(catalog: Catalog, record: FileRecord, grants: list[TccGrant]) -> InventoryItem:
    matched = tcc_grants_for(record, grants)
    flags = file_flags(record)
    if any(grant["auth"] == "allowed" for grant in matched):
        flags.append("tcc-granted")
    capabilities = []
    for cap in catalog.capabilities:
        evidence = cap.evidence(record["imports"], record["libraries"])
        if evidence:
            capabilities.append(CapabilityMatch(id=cap.id, evidence=evidence))
    note = catalog.note_for(record["path"])
    return InventoryItem(
        file=record,
        capabilities=capabilities,
        note=note.name if note else None,
        flags=flags,
        tcc=matched,
    )
