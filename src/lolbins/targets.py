"""Find the Macs and macOS VMs this host can reach, and the command that runs the probe on each.

The probe needs an argv that runs bash reading the script from stdin. This Mac, Parallels
(`prlctl exec`), Tart (`tart exec -i`) and SSH provide that directly. VMware Fusion's `vmrun` and
UTM's `utmctl` cannot attach stdin to a program in a macOS guest, so those guests are listed
without a command and with a note on how to reach them instead (SSH once Remote Login is on, or
running the probe script in the guest and importing its output).

Discovery only lists; it never starts, stops or logs in to anything.
"""

import json
import re
import shlex
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Literal, TypedDict

TargetKind = Literal["local", "parallels", "tart", "vmware-fusion", "utm", "ssh"]
CheckStatus = Literal["found", "not-installed", "error"]
Runner = Callable[[list[str]], str]

LOCAL_SHELL = ["/bin/bash", "-s"]
# BatchMode stops ssh asking for a password, which it would otherwise read from the probe script.
SSH_OPTIONS = ["-o", "BatchMode=yes"]
VMRUN_APP_PATH = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
UTMCTL_APP_PATH = "/Applications/UTM.app/Contents/MacOS/utmctl"
SSH_HOST_LINE = re.compile(r"\s*host\s*[=\s]\s*(?P<aliases>.+)", re.IGNORECASE)
NO_STDIN_NOTE = (
    "{tool} cannot attach stdin to a program in a macOS guest, so there is no direct command. "
    "Either turn on Remote Login in the guest and scan with "
    "['ssh', '-o', 'BatchMode=yes', 'user@<guest address>', '/bin/bash', '-s'], "
    "or run get_probe_script's script in the guest yourself and pass its output to "
    "import_probe_output."
)


class Target(TypedDict):
    """A Mac or VM the probe may reach, and the argv that pipes the probe into it."""

    kind: TargetKind
    name: str
    state: str
    command: list[str] | None
    note: str


class ProviderCheck(TypedDict):
    """What discovery found when it looked for one kind of target."""

    kind: TargetKind
    status: CheckStatus
    detail: str


class Discovery(TypedDict):
    """Every target found, plus what was checked and why a kind may have found nothing."""

    targets: list[Target]
    checked: list[ProviderCheck]


class DiscoveryError(RuntimeError):
    """A hypervisor CLI is installed but listing its VMs failed."""


def run_listing(argv: list[str]) -> str:
    """Run a listing command and return its stdout.

    Raises:
        DiscoveryError: If the command fails or takes longer than 20 seconds.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(f"{shlex.join(argv)} did not answer within 20s") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip()[-500:] or "(no stderr)"
        raise DiscoveryError(f"{shlex.join(argv)} exited {proc.returncode}: {detail}")
    return proc.stdout


def find_tool(name: str, app_path: str | None = None) -> str | None:
    """Return the path of a CLI on PATH, or inside its app bundle when it is not on PATH."""
    found = shutil.which(name)
    if found:
        return found
    if app_path and Path(app_path).is_file():
        return app_path
    return None


def discover(
    run: Runner = run_listing,
    which: Callable[[str, str | None], str | None] = find_tool,
    ssh_config: Path | None = None,
    platform: str = sys.platform,
) -> Discovery:
    """List every target reachable from this host.

    Args:
        run: Runs a listing argv and returns stdout; raises DiscoveryError on failure.
        which: Locates a CLI by name, with an optional app-bundle fallback path.
        ssh_config: The ssh client config to read Host aliases from (default ~/.ssh/config).
        platform: sys.platform of this host; only a Mac can be scanned locally.

    Returns:
        The targets, and one check per kind explaining what was found.
    """
    discovery = Discovery(targets=[], checked=[])
    if platform == "darwin":
        discovery["targets"].append(_local_target())
        discovery["checked"].append(ProviderCheck(kind="local", status="found", detail="this Mac"))
    else:
        discovery["checked"].append(
            ProviderCheck(kind="local", status="not-installed", detail=f"this host is {platform}")
        )
    providers: list[tuple[TargetKind, str, str | None, Callable[[Runner, str], list[Target]]]] = [
        ("parallels", "prlctl", None, _parallels),
        ("tart", "tart", None, _tart),
        ("vmware-fusion", "vmrun", VMRUN_APP_PATH, _vmware_fusion),
        ("utm", "utmctl", UTMCTL_APP_PATH, _utm),
    ]
    for kind, tool_name, app_path, lister in providers:
        tool = which(tool_name, app_path)
        if tool is None:
            discovery["checked"].append(
                ProviderCheck(kind=kind, status="not-installed", detail=f"{tool_name} not found")
            )
            continue
        _collect(discovery, kind, partial(lister, run, tool))
    _collect(discovery, "ssh", partial(_ssh_hosts, ssh_config or Path.home() / ".ssh" / "config"))
    return discovery


def _collect(
    discovery: Discovery, kind: TargetKind, list_targets: Callable[[], list[Target]]
) -> None:
    try:
        targets = list_targets()
    except (DiscoveryError, OSError, ValueError) as exc:
        discovery["checked"].append(ProviderCheck(kind=kind, status="error", detail=str(exc)))
        return
    discovery["targets"].extend(targets)
    discovery["checked"].append(
        ProviderCheck(kind=kind, status="found", detail=f"{len(targets)} target(s)")
    )


def _local_target() -> Target:
    return Target(
        kind="local",
        name=socket.gethostname(),
        state="running",
        command=LOCAL_SHELL,
        note="This Mac, as the user running the MCP server. The TCC databases are readable only "
        "if the app hosting the server has Full Disk Access.",
    )


def _parallels(run: Runner, prlctl: str) -> list[Target]:
    vms = json.loads(run([prlctl, "list", "--all", "--info", "--json"]))
    targets = []
    for vm in vms:
        if vm.get("OS") != "macosx":
            continue
        name, state = str(vm["Name"]), str(vm.get("State", "unknown"))
        note = "Needs Parallels Tools in the guest and a user logged in to its desktop."
        if state != "running":
            note += f" Start it first: prlctl start {shlex.quote(name)}."
        command = [prlctl, "exec", name, "--current-user", *LOCAL_SHELL]
        targets.append(Target(kind="parallels", name=name, state=state, command=command, note=note))
    return targets


def _tart(run: Runner, tart: str) -> list[Target]:
    vms = json.loads(run([tart, "list", "--source", "local", "--format", "json"]))
    targets = []
    for vm in vms:
        name, state = str(vm["Name"]), str(vm.get("State", "unknown"))
        note = (
            "Needs the Tart Guest Agent in the guest (Cirrus Labs images include it). Tart also "
            "runs Linux guests; the probe fails on those."
        )
        if state != "running":
            note += f" Start it first: tart run {shlex.quote(name)}."
        command = [tart, "exec", "-i", name, *LOCAL_SHELL]
        targets.append(Target(kind="tart", name=name, state=state, command=command, note=note))
    return targets


def _vmware_fusion(run: Runner, vmrun: str) -> list[Target]:
    lines = run([vmrun, "-T", "fusion", "list"]).splitlines()
    note = NO_STDIN_NOTE.format(tool="vmrun") + (
        " vmrun -T fusion getGuestIPAddress <vmx> -wait prints the guest address."
    )
    return [
        Target(kind="vmware-fusion", name=line.strip(), state="running", command=None, note=note)
        for line in lines[1:]
        if line.strip()
    ]


def _utm(run: Runner, utmctl: str) -> list[Target]:
    lines = run([utmctl, "list"]).splitlines()
    targets = []
    for line in lines[1:]:
        fields = line.split(maxsplit=2)
        if len(fields) != 3:
            continue
        _, state, name = fields
        note = NO_STDIN_NOTE.format(tool="utmctl exec")
        targets.append(Target(kind="utm", name=name, state=state, command=None, note=note))
    return targets


def _ssh_hosts(config: Path) -> list[Target]:
    if not config.is_file():
        return []
    aliases: dict[str, None] = {}
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SSH_HOST_LINE.fullmatch(line)
        if match is None:
            continue
        for alias in match["aliases"].split():
            if not any(c in alias for c in "*?!"):
                aliases[alias] = None
    note = (
        "A Host alias from your ssh config; it may not be a Mac. Needs key-based login, since "
        "BatchMode stops ssh prompting for a password. Included files are not read."
    )
    return [
        Target(
            kind="ssh",
            name=alias,
            state="configured",
            command=["ssh", *SSH_OPTIONS, alias, *LOCAL_SHELL],
            note=note,
        )
        for alias in aliases
    ]
