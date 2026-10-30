"""Run probe.sh on a target and parse its output.

probe.sh prints one tab-separated record per line:

    H  key  value                                       host fact
    P  perms  owner  group  size  flags  path           stat -L of an existing path; flags are
                                                        BSD file flags such as restricted, or -
    S  sha256  path                                     SHA-256 of a readable file
    F  path  link_target  is_script  codesign  ents     codesign -dv text and entitlements
                                                        plist, both base64-encoded
    M  path                                             path does not exist
    W  whatis_line                                      man-page summary line from whatis
    D  scope  status  detail                            a TCC database: scope is system or
                                                        user, status ok, unreadable or missing
    T  scope  service  client  client_type  auth  object   one TCC grant from that database
    X  path  label  context  plist  services  markers   launchd Mach services and static XPC
                                                        listener markers; JSON/text are base64
    E  ok                                               end marker; absent means truncated
"""

import base64
import binascii
import json
import plistlib
import re
import shlex
import subprocess
from collections.abc import Iterable, Sequence
from datetime import datetime
from importlib import resources
from pathlib import PurePosixPath
from typing import Any, Literal, TypedDict

HEREDOC_DELIMITER = "__LOLBINS_EOF__"
SHIM_IDENTIFIER_PREFIX = "com.apple.dt.xcode_select.tool-shim"
RECORD_FIELDS = {
    "H": 2,
    "P": 6,
    "S": 2,
    "F": 5,
    "M": 1,
    "W": 1,
    "D": 3,
    "T": 6,
    "X": 6,
    "E": 1,
}
WHATIS_NAME = re.compile(r"(?P<name>[^\s(]+)\((?P<section>[^)]*)\)")
SECTION_RANK = {"1": 0, "8": 1}

SigningState = Literal["signed", "adhoc", "unsigned", "unreadable"]
TccScope = Literal["system", "user"]
TccStatus = Literal["ok", "unreadable", "missing"]
TccAuth = Literal["denied", "unknown", "allowed", "limited", "other"]
TCC_AUTH: dict[str, TccAuth] = {"0": "denied", "1": "unknown", "2": "allowed", "3": "limited"}
# TCC.db stores this placeholder when a grant has no target object.
TCC_NO_OBJECT = "UNUSED"
XPC_LISTENER_MARKERS = {
    "NSXPCListener",
    "shouldAcceptNewConnection",
    "xpc_main",
    "xpc_connection_create_mach_service",
    "xpc_connection_set_event_handler",
}


class ProbeError(RuntimeError):
    """The probe could not be run or produced output that cannot be parsed."""


class Signing(TypedDict):
    """Code-signing summary parsed from codesign output."""

    state: SigningState
    identifier: str | None
    authorities: list[str]
    team_id: str | None
    platform_binary: bool
    format: str | None
    flags: list[str]
    error: str | None


class XpcMachService(TypedDict):
    """One Mach service name and its exact launchd registration properties."""

    name: str
    properties: Any


class XpcRegistration(TypedDict):
    """A launchd job that registers Mach services using this executable."""

    label: str
    run_context: Literal["system", "user"]
    plist_path: str
    mach_services: list[XpcMachService]
    listener_markers: list[str]


class FileRecord(TypedDict):
    """Everything the probe learned about one path on the target."""

    path: str
    summary: str | None
    link_target: str | None
    is_script: bool
    is_dev_shim: bool
    perms: str | None
    owner: str | None
    group: str | None
    size: int | None
    sha256: str | None
    bsd_flags: list[str]
    signing: Signing
    entitlements: dict[str, Any]
    xpc: list[XpcRegistration]


class TccSource(TypedDict):
    """Whether the probe could read one TCC database."""

    scope: TccScope
    status: TccStatus
    detail: str


class TccGrant(TypedDict):
    """One row of a TCC database: a client's recorded decision for a service.

    client_type "path" means client is an absolute path; "bundle" means a bundle or signing
    identifier. auth names TCC.db's auth_value (0 denied, 1 unknown, 2 allowed, 3 limited) and
    is "other" for any other code; auth_value keeps the raw code. target is the object of the
    grant, such as the app an Automation grant may control, or None.
    """

    scope: TccScope
    service: str
    client: str
    client_type: Literal["bundle", "path"]
    auth: TccAuth
    auth_value: int
    target: str | None


class TccSnapshot(TypedDict):
    """The TCC databases the probe tried to read and every grant it found."""

    sources: list[TccSource]
    grants: list[TccGrant]


class ProbeOutput(TypedDict):
    """Parsed probe output: host facts, files keyed by path, missing paths and TCC grants."""

    facts: dict[str, str]
    files: dict[str, FileRecord]
    missing: list[str]
    tcc: TccSnapshot


def parallels_command(vm: str) -> list[str]:
    """Return the argv that pipes a script into bash inside a Parallels VM as the GUI user."""
    return ["prlctl", "exec", vm, "--current-user", "/bin/bash", "-s"]


def build_script(scan_dirs: Sequence[str], extra_paths: Sequence[str]) -> str:
    """Prefix probe.sh with heredoc assignments carrying its inputs."""
    body = resources.files("lolbins").joinpath("probe.sh").read_text(encoding="utf-8")
    preamble = _heredoc_assignment("LOLBINS_SCAN_DIRS", scan_dirs) + _heredoc_assignment(
        "LOLBINS_EXTRA_PATHS", extra_paths
    )
    return preamble + body


def run_probe(
    command: Sequence[str],
    scan_dirs: Sequence[str],
    extra_paths: Sequence[str],
    timeout: float,
) -> ProbeOutput:
    """Pipe the probe into `command` (which must run bash reading stdin) and parse the result.

    Raises:
        ProbeError: If the command is missing, fails, times out, or its output is malformed.
    """
    script = build_script(scan_dirs, extra_paths)
    try:
        proc = subprocess.run(
            list(command),
            input=script,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ProbeError(
            f"cannot run {command[0]!r}: not found on PATH. "
            "Is Parallels Desktop installed (prlctl ships with it)?"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ProbeError(
            f"probe did not finish within {timeout:.0f}s; raise --timeout or check the VM"
        ) from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip()[-2000:] or "(no stderr)"
        raise ProbeError(
            f"probe failed with exit code {proc.returncode} running {shlex.join(command)}: "
            f"{detail}. Check that the VM is running and a user is logged in."
        )
    return parse_output(proc.stdout)


def parse_output(text: str) -> ProbeOutput:
    """Parse probe.sh output into facts, per-file records and missing paths.

    Raises:
        ProbeError: On malformed records or when the end marker is absent.
    """
    records: dict[str, list[list[str]]] = {tag: [] for tag in RECORD_FIELDS}
    for line_no, line in enumerate(text.splitlines(), start=1):
        tag, fields = _split_record(line_no, line)
        records[tag].append(fields)
    if not records["E"]:
        raise ProbeError("probe output is truncated: end marker missing")

    stats = {f[5]: (f[0], f[1], f[2], int(f[3]), f[4]) for f in records["P"]}
    hashes = {f[1]: f[0] for f in records["S"]}
    summaries = parse_whatis(f[0] for f in records["W"])
    xpc_by_path: dict[str, list[XpcRegistration]] = {}
    for fields in records["X"]:
        path, registration = _xpc_registration(fields)
        xpc_by_path.setdefault(path, []).append(registration)
    files = {
        f[0]: _file_record(
            f,
            stats.get(f[0]),
            hashes.get(f[0]),
            summaries.get(PurePosixPath(f[0]).name),
            xpc_by_path.get(f[0], []),
        )
        for f in records["F"]
    }
    return ProbeOutput(
        facts={key: value for key, value in records["H"]},
        files=files,
        missing=[f[0] for f in records["M"]],
        tcc=TccSnapshot(
            sources=[_tcc_source(f) for f in records["D"]],
            grants=[_tcc_grant(f) for f in records["T"]],
        ),
    )


def parse_whatis(lines: Iterable[str]) -> dict[str, str]:
    """Map command names to their man-page summary from `whatis` output lines.

    A line looks like `name1(1), name2(8) - summary`. When a name appears on several lines,
    the most specific page wins: fewest names on the line, then section 1, then section 8.
    For example `log` resolves to log(1) rather than the shell built-ins page that also
    lists it.
    """
    best: dict[str, tuple[tuple[int, int], str]] = {}
    for line in lines:
        names_part, sep, summary = line.partition(" - ")
        if not sep:
            continue
        names = [name.strip() for name in names_part.split(",")]
        for name in names:
            match = WHATIS_NAME.fullmatch(name)
            if match is None:
                continue
            rank = (len(names), SECTION_RANK.get(match["section"][:1], len(SECTION_RANK)))
            current = best.get(match["name"])
            if current is None or rank < current[0]:
                best[match["name"]] = (rank, summary.strip())
    return {name: summary for name, (_, summary) in best.items()}


def parse_codesign(text: str) -> Signing:
    """Parse `codesign -dv --verbose=2` stderr into a Signing summary."""
    values: dict[str, str] = {}
    authorities: list[str] = []
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "Authority":
            authorities.append(value)
        elif key == "CodeDirectory v":
            values["flags"] = value
        else:
            values.setdefault(key, value)

    if "Identifier" not in values:
        lines = text.strip().splitlines()
        return Signing(
            state="unsigned" if "not signed at all" in text else "unreadable",
            identifier=None,
            authorities=[],
            team_id=None,
            platform_binary=False,
            format=None,
            flags=[],
            error=lines[-1] if lines else "codesign produced no output",
        )

    team_id = values.get("TeamIdentifier")
    return Signing(
        state="adhoc" if values.get("Signature") == "adhoc" else "signed",
        identifier=values["Identifier"],
        authorities=authorities,
        team_id=None if team_id in (None, "not set") else team_id,
        platform_binary="Platform identifier" in values,
        format=values.get("Format"),
        flags=_code_directory_flags(values.get("flags", "")),
        error=None,
    )


def _code_directory_flags(code_directory: str) -> list[str]:
    _, _, rest = code_directory.partition("flags=")
    start, end = rest.find("("), rest.find(")")
    if start == -1 or end == -1:
        return []
    names = rest[start + 1 : end]
    return [] if names == "none" else names.split(",")


def _heredoc_assignment(name: str, lines: Sequence[str]) -> str:
    for line in lines:
        if "\n" in line or line == HEREDOC_DELIMITER:
            raise ProbeError(f"{name}: {line!r} cannot be passed to the probe")
    body = "\n".join(lines)
    return f"{name}=$(cat <<'{HEREDOC_DELIMITER}'\n{body}\n{HEREDOC_DELIMITER}\n)\n"


def _split_record(line_no: int, line: str) -> tuple[str, list[str]]:
    tag, _, rest = line.partition("\t")
    expected = RECORD_FIELDS.get(tag)
    if expected is None:
        raise ProbeError(f"probe output line {line_no}: unknown record {line[:120]!r}")
    fields = rest.split("\t")
    if len(fields) != expected:
        raise ProbeError(
            f"probe output line {line_no}: {tag} record has {len(fields)} fields, "
            f"expected {expected}: {line[:120]!r}"
        )
    return tag, fields


def _tcc_source(fields: list[str]) -> TccSource:
    scope, status, detail = fields
    if scope not in ("system", "user") or status not in ("ok", "unreadable", "missing"):
        raise ProbeError(f"probe sent an unknown TCC database record: {fields!r}")
    return TccSource(scope=scope, status=status, detail=detail)


def _tcc_grant(fields: list[str]) -> TccGrant:
    scope, service, client, client_type, auth, target = fields
    if scope not in ("system", "user") or client_type not in ("0", "1") or not auth.isdigit():
        raise ProbeError(f"probe sent an unknown TCC grant record: {fields!r}")
    return TccGrant(
        scope=scope,
        service=service,
        client=client,
        client_type="path" if client_type == "1" else "bundle",
        auth=TCC_AUTH.get(auth, "other"),
        auth_value=int(auth),
        target=None if target in ("", TCC_NO_OBJECT) else target,
    )


def _xpc_registration(fields: list[str]) -> tuple[str, XpcRegistration]:
    path, label, run_context, plist_path, services_b64, markers_b64 = fields
    if run_context not in ("system", "user"):
        raise ProbeError(f"probe sent an unknown XPC run context: {run_context!r}")
    try:
        services = json.loads(_b64decode(services_b64, path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{path}: XPC MachServices data is not valid JSON: {exc}") from exc
    if not isinstance(services, dict) or not services:
        raise ProbeError(f"{path}: XPC MachServices data must be a non-empty dictionary")
    markers = _b64decode(markers_b64, path).decode("utf-8", errors="replace").splitlines()
    unknown = sorted(set(markers) - XPC_LISTENER_MARKERS)
    if unknown:
        raise ProbeError(f"{path}: probe sent unknown XPC listener markers: {unknown}")
    return path, XpcRegistration(
        label=label,
        run_context=run_context,
        plist_path=plist_path,
        mach_services=[
            XpcMachService(name=str(name), properties=_jsonable(properties))
            for name, properties in sorted(services.items())
        ],
        listener_markers=sorted(set(markers)),
    )


def _file_record(
    fields: list[str],
    stat: tuple[str, str, str, int, str] | None,
    sha256: str | None,
    summary: str | None,
    xpc: list[XpcRegistration],
) -> FileRecord:
    path, link_target, is_script, codesign_b64, entitlements_b64 = fields
    signing = parse_codesign(_b64decode(codesign_b64, path).decode("utf-8", errors="replace"))
    perms, owner, group, size, flags = stat or (None, None, None, None, "-")
    identifier = signing["identifier"] or ""
    return FileRecord(
        path=path,
        summary=summary,
        link_target=link_target or None,
        is_script=is_script == "1",
        is_dev_shim=identifier.startswith(SHIM_IDENTIFIER_PREFIX),
        perms=perms,
        owner=owner,
        group=group,
        size=size,
        sha256=sha256,
        bsd_flags=[] if flags in ("", "-") else flags.split(","),
        signing=signing,
        entitlements=_parse_entitlements(entitlements_b64, path),
        xpc=xpc,
    )


def _b64decode(value: str, path: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ProbeError(f"{path}: probe sent invalid base64: {exc}") from exc


def _parse_entitlements(value: str, path: str) -> dict[str, Any]:
    data = _b64decode(value, path)
    if not data.strip():
        return {}
    try:
        parsed = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ProbeError(f"{path}: entitlements are not a valid plist: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProbeError(f"{path}: entitlements plist is not a dictionary")
    return {str(key): _jsonable(item) for key, item in parsed.items()}


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return "base64:" + base64.b64encode(value).decode("ascii")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, plistlib.UID):
        return value.data
    return value
