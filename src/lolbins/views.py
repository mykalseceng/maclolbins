"""Shape a scan into the records the MCP server returns.

Everything here is built from site_data(), the object the HTML report reads, so the server and
the report always agree on which binaries are shown and what is said about each one.
"""

from typing import Any, TypedDict

from lolbins.entitlements import RUNTIME_WEAKENERS, explain
from lolbins.probe import Signing, TccGrant, XpcRegistration
from lolbins.scan import ExampleRef, ScanResult
from lolbins.site import site_data
from lolbins.tcc import service_label

TCC_ALLOW_PREFIX = "com.apple.private.tcc.allow"


class NotInReport(ValueError):
    """A binary or filter value that the scan does not contain."""


class TechniqueInfo(TypedDict):
    """A MITRE ATT&CK technique and its page."""

    id: str
    name: str
    url: str


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
    tactics: list[str]
    techniques: list[str]
    privilege: str
    flags: list[str]
    entitlement_count: int


class LolbinDetail(TypedDict):
    """Everything the report says about one binary."""

    path: str
    name: str
    description: str | None
    abuse: str
    privilege: str
    tactics: list[str]
    techniques: list[TechniqueInfo]
    examples: list[ExampleRef]
    xpc_functionality: str | None
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
        self.files: list[dict[str, Any]] = data["inventory"]
        self.entries: dict[str, dict[str, Any]] = {e["name"]: e for e in data["entries"]}

    def rows(
        self, query: str = "", tactic: str = "", flag: str = "", entitlement: str = ""
    ) -> list[LolbinRow]:
        """Return the binaries in the report that pass every non-empty filter.

        Args:
            query: Case-insensitive text found in the path, name, description, tactic,
                technique, signing identifier or an entitlement key.
            tactic: An ATT&CK tactic, such as "Execution" (case-insensitive).
            flag: A file flag, such as "setuid" or "weakened-runtime".
            entitlement: An entitlement key, or a prefix of one such as "com.apple.private.tcc.".
        """
        rows = []
        for file in self.files:
            entry = self.entries[file["entry"]]
            if (
                (not query or query.lower() in _search_text(file, entry))
                and (not tactic or tactic.lower() in (t.lower() for t in entry["tactics"]))
                and (not flag or flag in file["flags"])
                and (
                    not entitlement or any(k.startswith(entitlement) for k in file["entitlements"])
                )
            ):
                rows.append(_row(file, entry))
        return rows

    def detail(self, binary: str) -> LolbinDetail:
        """Return everything the report says about one binary, by path or catalogue name.

        Raises:
            NotInReport: If no binary in the report has that path, or a name matches several.
        """
        file = self._resolve(binary)
        entry = self.entries[file["entry"]]
        signing: Signing = file["signing"]
        return LolbinDetail(
            path=file["path"],
            name=entry["name"],
            description=file["summary"] or entry["description"],
            abuse=entry["abuse"],
            privilege=entry["privilege"],
            tactics=entry["tactics"],
            techniques=[
                TechniqueInfo(id=t["id"], name=t["name"], url=attack_url(t["id"]))
                for t in entry["techniques"]
            ],
            examples=entry["examples"],
            xpc_functionality=entry["xpc_functionality"],
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

    def _resolve(self, binary: str) -> dict[str, Any]:
        by_path = [f for f in self.files if f["path"] == binary]
        if by_path:
            return by_path[0]
        by_name = [f for f in self.files if f["entry"] == binary]
        if len(by_name) == 1:
            return by_name[0]
        if by_name:
            paths = ", ".join(f["path"] for f in by_name)
            raise NotInReport(f"{binary!r} is catalogued at several paths ({paths}); pick one")
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
    if key.startswith(TCC_ALLOW_PREFIX) and isinstance(value, list):
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


def _row(file: dict[str, Any], entry: dict[str, Any]) -> LolbinRow:
    return LolbinRow(
        path=file["path"],
        name=entry["name"],
        description=file["summary"] or entry["description"],
        tactics=entry["tactics"],
        techniques=[t["id"] for t in entry["techniques"]],
        privilege=entry["privilege"],
        flags=file["flags"],
        entitlement_count=len(file["entitlements"]),
    )


def _search_text(file: dict[str, Any], entry: dict[str, Any]) -> str:
    parts = [
        file["path"],
        entry["name"],
        file["summary"] or "",
        entry["description"] or "",
        *entry["tactics"],
        *(f"{t['id']} {t['name']}" for t in entry["techniques"]),
        file["signing"]["identifier"] or "",
        *file["entitlements"],
    ]
    return "\n".join(parts).lower()
