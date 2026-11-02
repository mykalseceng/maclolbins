"""Shape a scan into the records the MCP server returns.

Everything here is built from site_data(), the object the HTML report reads, so the server and
the report always agree on which binaries are shown and what is said about each one.
"""

from pathlib import PurePosixPath
from typing import Any, TypedDict

from maclolbins.entitlements import RUNTIME_WEAKENERS, explain
from maclolbins.probe import Signing, TccGrant, XpcRegistration
from maclolbins.scan import ExampleRef, ScanResult
from maclolbins.site import site_data
from maclolbins.tcc import service_label

# Keys whose value lists TCC services granted without a consent prompt. Other
# com.apple.private.tcc.* keys (allow-prompting, manager.*) also list services but are not
# known to grant access to them, so they get no tcc_services.
TCC_GRANT_KEYS = frozenset(
    {"com.apple.private.tcc.allow", "com.apple.private.tcc.allow.overridable"}
)


class NotInReport(ValueError):
    """A binary or filter value that the scan does not contain."""


class TechniqueInfo(TypedDict):
    """A MITRE ATT&CK technique and its page."""

    id: str
    name: str
    url: str


class CapabilityInfo(TypedDict):
    """A capability a binary shows, with the imports or libraries that show it."""

    id: str
    title: str
    summary: str
    evidence: list[str]
    techniques: list[TechniqueInfo]


class TccService(TypedDict):
    """A TCC service identifier and its System Settings name."""

    service: str
    label: str


class EntitlementExplanation(TypedDict):
    """What an entitlement key means, from Apple's documentation or its namespace."""

    key: str
    title: str
    summary: str
    namespace: str
    documented: bool
    apple_docs_url: str | None
    weakens_runtime: str | None


class EntitlementInfo(EntitlementExplanation):
    """An entitlement a binary holds, with its exact value from the code signature."""

    value: Any
    tcc_services: list[TccService]


class TccGrantInfo(TccGrant):
    """A TCC grant naming the binary, with its service's System Settings name."""

    service_label: str


class FileInfo(TypedDict):
    """Filesystem facts about one binary."""

    link_target: str | None
    owner: str
    perms: str | None
    size: int | None
    sha256: str | None
    bsd_flags: list[str]
    sip_protected: bool


class LolbinRow(TypedDict):
    """One binary in the report, summarised for listing."""

    path: str
    name: str
    description: str | None
    score: int
    capabilities: list[str]
    tactics: list[str]
    techniques: list[str]
    privilege: str
    flags: list[str]
    entitlement_count: int
    has_note: bool


class LolbinDetail(TypedDict):
    """Everything the report says about one binary."""

    path: str
    name: str
    description: str | None
    score: int
    capabilities: list[CapabilityInfo]
    libraries: list[str]
    abuse: str | None
    privilege: str
    tactics: list[str]
    techniques: list[TechniqueInfo]
    examples: list[ExampleRef]
    flags: list[str]
    file: FileInfo
    signing: Signing
    hardened_runtime: bool
    entitlements: list[EntitlementInfo]
    tcc_grants: list[TccGrantInfo]
    xpc: list[XpcRegistration]


class ReportView:
    """The report data of one scan, indexed for lookups."""

    def __init__(self, scan: ScanResult) -> None:
        """Build the view from a scan whose catalog parts are current."""
        data = site_data(scan)
        self.files: list[dict[str, Any]] = sorted(
            data["inventory"], key=lambda f: (-f["score"], f["path"])
        )
        self.capabilities: dict[str, dict[str, Any]] = data["capabilities"]
        self.notes: dict[str, dict[str, Any]] = data["notes"]

    def rows(
        self,
        query: str = "",
        tactic: str = "",
        flag: str = "",
        entitlement: str = "",
        capability: str = "",
    ) -> list[LolbinRow]:
        """Return the binaries in the report that pass every non-empty filter, best evidence first.

        Args:
            query: Case-insensitive text found in the path, name, description, capability,
                tactic, technique, note, signing identifier or an entitlement key.
            tactic: An ATT&CK tactic, such as "Execution" (case-insensitive).
            flag: A file flag, such as "setuid" or "weakened-runtime".
            entitlement: An entitlement key, or a prefix of one such as "com.apple.private.tcc.".
            capability: A capability id, such as "fetches-urls".
        """
        filters = [
            lambda f: not query or query.lower() in self._search_text(f),
            lambda f: not tactic or tactic.lower() in (t.lower() for t in f["tactics"]),
            lambda f: not flag or flag in f["flags"],
            lambda f: not entitlement or any(k.startswith(entitlement) for k in f["entitlements"]),
            lambda f: not capability or capability in (c["id"] for c in f["capabilities"]),
        ]
        return [_row(f) for f in self.files if all(test(f) for test in filters)]

    def detail(self, binary: str) -> LolbinDetail:
        """Return everything the report says about one binary, by path or file name.

        Raises:
            NotInReport: If no binary in the report has that path, or a name matches several.
        """
        file = self._resolve(binary)
        note = self.notes.get(file["note"]) if file["note"] else None
        signing: Signing = file["signing"]
        return LolbinDetail(
            path=file["path"],
            name=_name(file),
            description=file["summary"],
            score=file["score"],
            capabilities=[self._capability_info(match) for match in file["capabilities"]],
            libraries=file["libraries"],
            abuse=note["abuse"] if note else None,
            privilege=file["privilege"],
            tactics=file["tactics"],
            techniques=[_technique_info(t) for t in file["techniques"]],
            examples=note["examples"] if note else [],
            flags=file["flags"],
            file=FileInfo(
                link_target=file["link"],
                owner=file["owner"],
                perms=file["perms"],
                size=file["size"],
                sha256=file["sha256"],
                bsd_flags=file["bsd_flags"],
                sip_protected="restricted" in file["bsd_flags"],
            ),
            signing=signing,
            hardened_runtime="runtime" in signing["flags"],
            entitlements=[
                entitlement_info(key, value) for key, value in sorted(file["entitlements"].items())
            ],
            tcc_grants=[
                TccGrantInfo(**grant, service_label=service_label(grant["service"]))
                for grant in file["tcc"]
            ],
            xpc=file["xpc"],
        )

    def _capability_info(self, match: dict[str, Any]) -> CapabilityInfo:
        cap = self.capabilities[match["id"]]
        return CapabilityInfo(
            id=cap["id"],
            title=cap["title"],
            summary=cap["summary"],
            evidence=match["evidence"],
            techniques=[_technique_info(t) for t in cap["techniques"]],
        )

    def _search_text(self, file: dict[str, Any]) -> str:
        parts = [
            file["path"],
            file["summary"] or "",
            file["note"] or "",
            *(self.capabilities[c["id"]]["title"] for c in file["capabilities"]),
            *(c["id"] for c in file["capabilities"]),
            *file["tactics"],
            *(f"{t['id']} {t['name']}" for t in file["techniques"]),
            file["signing"]["identifier"] or "",
            *file["entitlements"],
        ]
        return "\n".join(parts).lower()

    def _resolve(self, binary: str) -> dict[str, Any]:
        by_path = [f for f in self.files if f["path"] == binary]
        if by_path:
            return by_path[0]
        by_name = [f for f in self.files if _name(f) == binary]
        if len(by_name) == 1:
            return by_name[0]
        if by_name:
            paths = ", ".join(f["path"] for f in by_name)
            raise NotInReport(f"{binary!r} is in the report at several paths ({paths}); pick one")
        raise NotInReport(
            f"{binary!r} is not a binary in this scan's report; list_lolbins shows the paths"
        )


def explain_entitlement(key: str) -> EntitlementExplanation:
    """Return what an entitlement key means and where Apple documents it."""
    info = explain(key)
    return EntitlementExplanation(
        key=key,
        title=info.title,
        summary=info.summary,
        namespace=info.namespace,
        documented=info.documented,
        apple_docs_url=info.url or None,
        weakens_runtime=RUNTIME_WEAKENERS.get(key),
    )


def entitlement_info(key: str, value: Any) -> EntitlementInfo:
    """Explain an entitlement a binary holds, naming any TCC services its value lists."""
    services: list[TccService] = []
    if key in TCC_GRANT_KEYS and isinstance(value, list):
        services = [
            TccService(service=item, label=service_label(item))
            for item in value
            if isinstance(item, str)
        ]
    info = EntitlementInfo(**explain_entitlement(key), value=value, tcc_services=services)
    if value is not True:
        info["weakens_runtime"] = None
    return info


def attack_url(technique_id: str) -> str:
    """Return the MITRE ATT&CK page for a technique ID such as T1059.002."""
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def _technique_info(technique: dict[str, Any]) -> TechniqueInfo:
    return TechniqueInfo(
        id=technique["id"], name=technique["name"], url=attack_url(technique["id"])
    )


def _name(file: dict[str, Any]) -> str:
    return PurePosixPath(file["path"]).name


def _row(file: dict[str, Any]) -> LolbinRow:
    return LolbinRow(
        path=file["path"],
        name=_name(file),
        description=file["summary"],
        score=file["score"],
        capabilities=[c["id"] for c in file["capabilities"]],
        tactics=file["tactics"],
        techniques=[t["id"] for t in file["techniques"]],
        privilege=file["privilege"],
        flags=file["flags"],
        entitlement_count=len(file["entitlements"]),
        has_note=file["note"] is not None,
    )
