"""MCP server over lolbins scans, speaking protocol revision 2026-07-28 (mcp SDK 2.x).

The server keeps no state between requests. A scan is named by the scan_id that scan_target or
import_probe_output returns; it is the name of the scan's report directory, so scans written by
`lolbins scan` are served too. Every answer about a binary comes from the same data the HTML
report shows (see lolbins.views).

The server never decides how to reach a target. scan_target pipes the probe into whatever argv
the agent passes; discover_targets lists what this host can reach and suggests an argv for each.
"""

from functools import partial
from importlib.metadata import version
from pathlib import Path
from typing import Annotated, TypedDict

import anyio
from mcp.server import CacheHint
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from lolbins.catalog import Catalog
from lolbins.probe import ProbeError, TccSource, build_script, parse_output, run_probe
from lolbins.reports import scan_ids, scan_path, write_report
from lolbins.scan import (
    DEFAULT_SCAN_DIRS,
    ScanFileError,
    ScanResult,
    build_scan,
    load_scan,
    rejoin_catalog,
)
from lolbins.targets import Discovery, discover
from lolbins.views import (
    EntitlementExplanation,
    LolbinDetail,
    LolbinRow,
    NotInReport,
    ReportView,
    explain_entitlement,
)

INSTRUCTIONS = """\
Enumerates macOS living-off-the-land binaries (LOLBins) on a Mac or macOS VM: what each one is,
how it is abused (MITRE ATT&CK), its code signature, every entitlement with Apple's documentation
link, SIP protection and TCC grants.

1. Work out where the binaries live. discover_targets lists this Mac, Parallels, Tart, VMware
   Fusion and UTM VMs and ssh hosts, each with a suggested command. Pick the target the user
   means; ask them when it is ambiguous.
2. Scan it with scan_target(command, target). command is any argv that runs bash reading a
   script from stdin on the target, such as ["/bin/bash", "-s"] for this Mac or
   ["ssh", "-o", "BatchMode=yes", "user@host", "/bin/bash", "-s"]. When no such argv exists,
   run get_probe_script's script on the target by any means and pass its saved stdout to
   import_probe_output.
3. Both return a scan_id. Pass it to list_lolbins and get_lolbin. list_scans shows earlier scans.
"""
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
RUNS_COMMAND = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
WRITES_REPORT = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
)

ScanId = Annotated[str, Field(description="A scan_id from list_scans or scan_target")]


class ScanSummary(TypedDict):
    """A saved scan: what was scanned, when, and where its HTML report is."""

    scan_id: str
    target: str
    collected_at: str | None
    product_version: str | None
    build_version: str | None
    report: str
    lolbins_in_report: int
    catalogued_present: int
    catalogued_absent: list[str]
    tcc_sources: list[TccSource]


class UnreadableScan(TypedDict):
    """A report directory whose scan.json cannot be served."""

    scan_id: str
    error: str


class ScanListing(TypedDict):
    """Every saved scan, newest first, and any that cannot be read."""

    scans: list[ScanSummary]
    unreadable: list[UnreadableScan]


class ProbeScript(TypedDict):
    """The probe script and how to run it without scan_target."""

    script: str
    usage: str


class Tools:
    """The server's tools, bound to a reports directory and a catalog."""

    def __init__(self, reports_dir: Path, catalog: Catalog) -> None:
        """Serve scans under reports_dir, joined against catalog."""
        self.reports_dir = reports_dir
        self.catalog = catalog

    async def discover_targets(self) -> Discovery:
        """List the Macs and macOS VMs this host can reach, with a scan command for each.

        Checks this Mac, Parallels, Tart, VMware Fusion, UTM and Host aliases in ~/.ssh/config.
        A target with no command cannot take the probe on stdin; its note says how to reach it.
        Starts and logs in to nothing.
        """
        return await anyio.to_thread.run_sync(discover)

    async def scan_target(
        self,
        command: Annotated[
            list[str],
            Field(
                min_length=1,
                description="argv run on this host that starts bash reading a script from "
                'stdin on the target, e.g. ["prlctl", "exec", "macOS", "--current-user", '
                '"/bin/bash", "-s"]',
            ),
        ],
        target: Annotated[str, Field(min_length=1, description="Name for the scan, e.g. a VM")],
        ctx: Context,
        timeout_seconds: Annotated[float, Field(gt=0, le=3600)] = 900,
    ) -> ScanSummary:
        """Run the read-only probe on a target and save the scan and its HTML report.

        Runs `command` on this host and pipes the probe script into it. The probe reads file
        metadata, code signatures, entitlements, man-page summaries, launchd plists and the TCC
        databases; it writes nothing outside its own temp directory. A full scan takes one to
        two minutes.
        """
        await ctx.report_progress(0, 1, f"probing {target}")
        probe_run = partial(
            run_probe, command, DEFAULT_SCAN_DIRS, self.catalog.all_paths(), timeout_seconds
        )
        try:
            probe = await anyio.to_thread.run_sync(probe_run)
        except ProbeError as exc:
            raise ToolError(f"scan of {target} failed: {exc}") from exc
        await ctx.report_progress(1, 1, "saving report")
        return self._save(build_scan(self.catalog, probe, target, list(DEFAULT_SCAN_DIRS)))

    def get_probe_script(self) -> ProbeScript:
        """Return the probe script, for targets that scan_target cannot pipe into."""
        return ProbeScript(
            script=build_script(DEFAULT_SCAN_DIRS, self.catalog.all_paths()),
            usage="Save the script on the target and run `/bin/bash probe.sh > probe.out` as "
            "the user whose view of the system you want. Copy probe.out back to this host and "
            "call import_probe_output with its path.",
        )

    def import_probe_output(
        self,
        output_path: Annotated[str, Field(description="Path on this host of the saved stdout")],
        target: Annotated[str, Field(min_length=1, description="Name for the scan, e.g. a VM")],
    ) -> ScanSummary:
        """Save a scan and its HTML report from probe output captured on the target."""
        try:
            text = Path(output_path).expanduser().read_text(encoding="utf-8", errors="replace")
            probe = parse_output(text)
        except OSError as exc:
            raise ToolError(f"cannot read probe output {output_path}: {exc}") from exc
        except ProbeError as exc:
            raise ToolError(f"{output_path} is not complete probe output: {exc}") from exc
        return self._save(build_scan(self.catalog, probe, target, list(DEFAULT_SCAN_DIRS)))

    def list_scans(self) -> ScanListing:
        """List saved scans, newest first, with the target, macOS version and report path."""
        listing = ScanListing(scans=[], unreadable=[])
        for scan_id in scan_ids(self.reports_dir):
            try:
                scan = self._load(scan_id)
            except ToolError as exc:
                listing["unreadable"].append(UnreadableScan(scan_id=scan_id, error=str(exc)))
                continue
            listing["scans"].append(self._summary(scan_id, scan))
        listing["scans"].sort(key=lambda s: s["collected_at"] or "", reverse=True)
        return listing

    def list_lolbins(
        self,
        scan_id: ScanId,
        query: Annotated[
            str, Field(description="Text in the path, name, description, technique or keys")
        ] = "",
        tactic: Annotated[str, Field(description='ATT&CK tactic, e.g. "Persistence"')] = "",
        flag: Annotated[
            str,
            Field(description="setuid, setgid, tcc-entitled, tcc-granted, weakened-runtime, ..."),
        ] = "",
        entitlement: Annotated[
            str, Field(description='Entitlement key or prefix, e.g. "com.apple.private.tcc."')
        ] = "",
    ) -> list[LolbinRow]:
        """List the LOLBins in a scan's report, optionally filtered; all filters must match."""
        return ReportView(self._load(scan_id)).rows(query, tactic, flag, entitlement)

    def get_lolbin(
        self,
        scan_id: ScanId,
        binary: Annotated[str, Field(description="Path such as /usr/bin/curl, or catalogue name")],
    ) -> LolbinDetail:
        """Return everything the report says about one binary.

        Includes its description, abuse notes, ATT&CK techniques with links, worked commands,
        file facts and SIP protection, code signature, every entitlement with its exact value
        and Apple documentation link, TCC grants and XPC-service evidence.
        """
        try:
            return ReportView(self._load(scan_id)).detail(binary)
        except NotInReport as exc:
            raise ToolError(str(exc)) from exc

    def explain_entitlement(
        self, key: Annotated[str, Field(description="Entitlement key exactly as signed")]
    ) -> EntitlementExplanation:
        """Explain an entitlement key and link Apple's page for it; needs no scan."""
        return explain_entitlement(key)

    def _load(self, scan_id: str) -> ScanResult:
        try:
            return rejoin_catalog(load_scan(scan_path(self.reports_dir, scan_id)), self.catalog)
        except ScanFileError as exc:
            raise ToolError(str(exc)) from exc

    def _save(self, scan: ScanResult) -> ScanSummary:
        try:
            out_dir = write_report(scan, self.reports_dir)
        except OSError as exc:
            raise ToolError(f"cannot save the scan under {self.reports_dir}: {exc}") from exc
        return self._summary(out_dir.name, scan)

    def _summary(self, scan_id: str, scan: ScanResult) -> ScanSummary:
        facts = scan["facts"]
        return ScanSummary(
            scan_id=scan_id,
            target=scan["target"],
            collected_at=facts.get("collected_at"),
            product_version=facts.get("product_version"),
            build_version=facts.get("build_version"),
            report=str(self.reports_dir / scan_id / "index.html"),
            lolbins_in_report=len(ReportView(scan).files),
            catalogued_present=sum(1 for e in scan["entries"] if e["status"] == "present"),
            catalogued_absent=[e["name"] for e in scan["entries"] if e["status"] != "present"],
            tcc_sources=scan["tcc"]["sources"],
        )


def build_server(reports_dir: Path, catalog: Catalog) -> MCPServer:
    """Return the lolbins MCP server, serving scans saved under reports_dir."""
    tools = Tools(reports_dir, catalog)
    server = MCPServer(
        name="lolbins",
        title="macOS LOLBins",
        version=version("lolbins"),
        instructions=INSTRUCTIONS,
        cache_hints={"tools/list": CacheHint(ttl_ms=3_600_000, scope="public")},
    )
    server.add_tool(tools.discover_targets, annotations=READ_ONLY)
    server.add_tool(tools.scan_target, annotations=RUNS_COMMAND)
    server.add_tool(tools.get_probe_script, annotations=READ_ONLY)
    server.add_tool(tools.import_probe_output, annotations=WRITES_REPORT)
    for read_only in (
        tools.list_scans,
        tools.list_lolbins,
        tools.get_lolbin,
        tools.explain_entitlement,
    ):
        server.add_tool(read_only, annotations=READ_ONLY)
    return server
