"""Load and validate the LOLBin catalog (catalog.toml)."""

import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

PRIVILEGES = ("user", "root")


class CatalogError(ValueError):
    """The catalog file is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique and the tactics it belongs to."""

    id: str
    name: str
    tactics: tuple[str, ...]


@dataclass(frozen=True)
class Example:
    """One worked command for a catalogued binary, and what it actually does."""

    title: str
    command: str
    explanation: str
    privilege: str


@dataclass(frozen=True)
class Entry:
    """One catalogued binary (or group of equivalent binaries) and how it is abused."""

    name: str
    paths: tuple[str, ...]
    techniques: tuple[str, ...]
    privilege: str
    abuse: str
    xpc_functionality: str | None = None
    examples: tuple[Example, ...] = ()


@dataclass(frozen=True)
class Catalog:
    """A validated catalog: technique definitions plus binary entries."""

    version: str
    techniques: dict[str, Technique]
    entries: tuple[Entry, ...]

    def tactics_for(self, entry: Entry) -> list[str]:
        """Return the distinct ATT&CK tactics covered by an entry, in first-seen order."""
        seen: dict[str, None] = {}
        for technique_id in entry.techniques:
            for tactic in self.techniques[technique_id].tactics:
                seen[tactic] = None
        return list(seen)

    def all_paths(self) -> list[str]:
        """Return every path referenced by any entry, deduplicated, in catalog order."""
        return list(dict.fromkeys(path for entry in self.entries for path in entry.paths))


def default_catalog_path() -> Path:
    """Return the catalog.toml shipped with the package."""
    return Path(str(resources.files("lolbins").joinpath("catalog.toml")))


def load_catalog(path: Path | None = None) -> Catalog:
    """Parse and validate a catalog file.

    Args:
        path: Catalog TOML file; defaults to the packaged catalog.

    Returns:
        The validated catalog.

    Raises:
        CatalogError: If the file is missing required fields or references unknown techniques.
    """
    path = path or default_catalog_path()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise CatalogError(f"{path}: invalid TOML: {exc}") from exc

    techniques = _parse_techniques(raw.get("techniques", {}), path)
    entries = tuple(_parse_entry(item, techniques, path) for item in raw.get("binary", []))
    if not entries:
        raise CatalogError(f"{path}: no [[binary]] entries")
    _check_consistency(entries, techniques, path)

    version = raw.get("meta", {}).get("version")
    if not isinstance(version, str):
        raise CatalogError(f"{path}: [meta] version must be a string")
    return Catalog(version=version, techniques=techniques, entries=entries)


def _parse_techniques(raw: dict[str, Any], path: Path) -> dict[str, Technique]:
    techniques: dict[str, Technique] = {}
    for technique_id, body in raw.items():
        name = body.get("name")
        tactics = body.get("tactics")
        if not isinstance(name, str) or not isinstance(tactics, list) or not tactics:
            raise CatalogError(f"{path}: technique {technique_id} needs a name and tactics")
        techniques[technique_id] = Technique(technique_id, name, tuple(tactics))
    return techniques


def _parse_entry(raw: dict[str, Any], techniques: dict[str, Technique], path: Path) -> Entry:
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise CatalogError(f"{path}: a [[binary]] entry has no name")
    where = f"{path}: binary {name!r}"
    paths = _parse_paths(raw.get("paths"), where)
    technique_ids = _parse_technique_ids(raw.get("techniques"), techniques, where)

    privilege = raw.get("privilege")
    if privilege not in PRIVILEGES:
        raise CatalogError(f"{where}: privilege must be one of {PRIVILEGES}, got {privilege!r}")

    abuse = raw.get("abuse")
    if not isinstance(abuse, str) or not abuse:
        raise CatalogError(f"{where}: abuse is required")

    xpc_functionality = raw.get("xpc_functionality")
    if xpc_functionality is not None and (
        not isinstance(xpc_functionality, str) or not xpc_functionality.strip()
    ):
        raise CatalogError(f"{where}: xpc_functionality must be a non-empty string")

    examples = tuple(_parse_example(item, where) for item in raw.get("example", []))
    return Entry(
        name=name,
        paths=paths,
        techniques=technique_ids,
        privilege=privilege,
        abuse=abuse,
        xpc_functionality=xpc_functionality,
        examples=examples,
    )


def _parse_example(raw: dict[str, Any], where: str) -> Example:
    fields = {}
    for field in ("title", "command", "explanation"):
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            raise CatalogError(f"{where}: every [[binary.example]] needs a non-empty {field}")
        fields[field] = value
    privilege = raw.get("privilege", "user")
    if privilege not in PRIVILEGES:
        raise CatalogError(
            f"{where}: example {fields['title']!r} privilege must be one of {PRIVILEGES}"
        )
    return Example(fields["title"], fields["command"], fields["explanation"], privilege)


def _parse_paths(raw: Any, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise CatalogError(f"{where}: paths must be a non-empty list")
    for item in raw:
        if not isinstance(item, str) or not item.startswith("/") or "\n" in item:
            raise CatalogError(f"{where}: path {item!r} must be absolute and single-line")
    return tuple(raw)


def _parse_technique_ids(raw: Any, techniques: dict[str, Technique], where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw:
        raise CatalogError(f"{where}: techniques must be a non-empty list")
    unknown = [t for t in raw if t not in techniques]
    if unknown:
        raise CatalogError(f"{where}: unknown techniques {unknown}; define them in [techniques]")
    return tuple(raw)


def _check_consistency(
    entries: tuple[Entry, ...], techniques: dict[str, Technique], path: Path
) -> None:
    names = [entry.name for entry in entries]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise CatalogError(f"{path}: duplicate binary names {duplicates}")

    owners: dict[str, str] = {}
    for entry in entries:
        for item in entry.paths:
            if item in owners:
                raise CatalogError(
                    f"{path}: path {item} is listed by both {owners[item]!r} and {entry.name!r}"
                )
            owners[item] = entry.name

    used = {t for entry in entries for t in entry.techniques}
    unused = sorted(set(techniques) - used)
    if unused:
        raise CatalogError(f"{path}: techniques defined but never used: {unused}")
