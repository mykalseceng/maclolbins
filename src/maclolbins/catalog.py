"""Load and validate the LOLBin catalog (catalog.toml): capability rules and path notes."""

import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

PRIVILEGES = ("user", "root")
CAPABILITY_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
MARKER = re.compile(r"[A-Za-z0-9_$.+-]+")


class CatalogError(ValueError):
    """The catalog file is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique and the tactics it belongs to."""

    id: str
    name: str
    tactics: tuple[str, ...]


@dataclass(frozen=True)
class Capability:
    """Something a binary can do, recognised by symbol names or library paths in its strings."""

    id: str
    title: str
    summary: str
    techniques: tuple[str, ...]
    symbols: tuple[str, ...]
    libraries: tuple[str, ...]

    def evidence(self, symbols: Iterable[str], library_paths: Iterable[str]) -> list[str]:
        """Return the symbols and library paths found in a binary that show this capability."""
        found = {symbol for symbol in symbols if symbol in self.symbols}
        found |= {lib for lib in library_paths if library_names(lib) & set(self.libraries)}
        return sorted(found)


@dataclass(frozen=True)
class Example:
    """One worked command from a note, and what it actually does."""

    title: str
    command: str
    explanation: str
    privilege: str


@dataclass(frozen=True)
class Note:
    """Hand-written abuse notes and worked commands for the binaries at some paths."""

    name: str
    paths: tuple[str, ...]
    techniques: tuple[str, ...]
    privilege: str
    abuse: str
    examples: tuple[Example, ...] = ()


@dataclass(frozen=True)
class Catalog:
    """A validated catalog: technique definitions, capability rules and notes."""

    version: str
    techniques: dict[str, Technique]
    capabilities: tuple[Capability, ...]
    notes: tuple[Note, ...]

    def tactics_for(self, technique_ids: Iterable[str]) -> list[str]:
        """Return the distinct ATT&CK tactics of some techniques, in first-seen order."""
        seen: dict[str, None] = {}
        for technique_id in technique_ids:
            for tactic in self.techniques[technique_id].tactics:
                seen[tactic] = None
        return list(seen)

    def all_symbols(self) -> list[str]:
        """Return every symbol any capability looks for, deduplicated and sorted."""
        return sorted({symbol for cap in self.capabilities for symbol in cap.symbols})

    def note_for(self, path: str) -> Note | None:
        """Return the note that covers a path, if any."""
        return next((note for note in self.notes if path in note.paths), None)


def library_names(path: str) -> set[str]:
    """Return the names a library path answers to: its file name and any framework it is in.

    Directories and version suffixes are dropped, so /usr/lib/libcurl.4.dylib is {libcurl},
    /System/Library/Frameworks/Tcl.framework/Versions/8.5/Tcl is {Tcl}, and a dylib inside a
    framework, such as Ruby.framework/.../libruby.2.6.dylib, is {Ruby, libruby}.
    """
    names = {path.rsplit("/", 1)[-1].split(".", 1)[0]}
    names.update(re.findall(r"/([^/]+)\.framework/", path))
    return names


def default_catalog_path() -> Path:
    """Return the catalog.toml shipped with the package."""
    return Path(str(resources.files("maclolbins").joinpath("catalog.toml")))


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
    capabilities = tuple(
        _parse_capability(item, techniques, path) for item in raw.get("capability", [])
    )
    if not capabilities:
        raise CatalogError(f"{path}: no [[capability]] rules")
    notes = tuple(_parse_note(item, techniques, path) for item in raw.get("note", []))
    _check_consistency(capabilities, notes, techniques, path)

    version = raw.get("meta", {}).get("version")
    if not isinstance(version, str):
        raise CatalogError(f"{path}: [meta] version must be a string")
    return Catalog(version=version, techniques=techniques, capabilities=capabilities, notes=notes)


def _parse_techniques(raw: dict[str, Any], path: Path) -> dict[str, Technique]:
    techniques: dict[str, Technique] = {}
    for technique_id, body in raw.items():
        name = body.get("name")
        tactics = body.get("tactics")
        if not isinstance(name, str) or not isinstance(tactics, list) or not tactics:
            raise CatalogError(f"{path}: technique {technique_id} needs a name and tactics")
        techniques[technique_id] = Technique(technique_id, name, tuple(tactics))
    return techniques


def _parse_capability(
    raw: dict[str, Any], techniques: dict[str, Technique], path: Path
) -> Capability:
    cap_id = raw.get("id")
    if not isinstance(cap_id, str) or not CAPABILITY_ID.fullmatch(cap_id):
        raise CatalogError(f"{path}: capability id {cap_id!r} must be lowercase-kebab-case")
    where = f"{path}: capability {cap_id!r}"
    for field in ("title", "summary"):
        if not isinstance(raw.get(field), str) or not raw[field].strip():
            raise CatalogError(f"{where}: {field} is required")
    symbols = _parse_markers(raw.get("symbols", []), "symbols", where)
    libraries = _parse_markers(raw.get("libraries", []), "libraries", where)
    if not symbols and not libraries:
        raise CatalogError(f"{where}: needs symbols, libraries or both")
    return Capability(
        id=cap_id,
        title=raw["title"],
        summary=raw["summary"],
        techniques=_parse_technique_ids(raw.get("techniques"), techniques, where),
        symbols=symbols,
        libraries=libraries,
    )


def _parse_markers(raw: Any, field: str, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise CatalogError(f"{where}: {field} must be a list")
    for item in raw:
        if not isinstance(item, str) or not MARKER.fullmatch(item):
            raise CatalogError(f"{where}: {field} entry {item!r} must be one token")
    return tuple(raw)


def _parse_note(raw: dict[str, Any], techniques: dict[str, Technique], path: Path) -> Note:
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise CatalogError(f"{path}: a [[note]] has no name")
    where = f"{path}: note {name!r}"
    privilege = raw.get("privilege")
    if privilege not in PRIVILEGES:
        raise CatalogError(f"{where}: privilege must be one of {PRIVILEGES}, got {privilege!r}")
    abuse = raw.get("abuse")
    if not isinstance(abuse, str) or not abuse:
        raise CatalogError(f"{where}: abuse is required")
    return Note(
        name=name,
        paths=_parse_paths(raw.get("paths"), where),
        techniques=_parse_technique_ids(raw.get("techniques"), techniques, where),
        privilege=privilege,
        abuse=abuse,
        examples=tuple(_parse_example(item, where) for item in raw.get("example", [])),
    )


def _parse_example(raw: dict[str, Any], where: str) -> Example:
    fields = {}
    for field in ("title", "command", "explanation"):
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            raise CatalogError(f"{where}: every [[note.example]] needs a non-empty {field}")
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
    capabilities: tuple[Capability, ...],
    notes: tuple[Note, ...],
    techniques: dict[str, Technique],
    path: Path,
) -> None:
    for kind, names in (
        ("capability ids", [cap.id for cap in capabilities]),
        ("note names", [note.name for note in notes]),
    ):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise CatalogError(f"{path}: duplicate {kind} {duplicates}")

    owners: dict[str, str] = {}
    for note in notes:
        for item in note.paths:
            if item in owners:
                raise CatalogError(
                    f"{path}: path {item} is in both note {owners[item]!r} and {note.name!r}"
                )
            owners[item] = note.name

    used = {t for item in (*capabilities, *notes) for t in item.techniques}
    unused = sorted(set(techniques) - used)
    if unused:
        raise CatalogError(f"{path}: techniques defined but never used: {unused}")
