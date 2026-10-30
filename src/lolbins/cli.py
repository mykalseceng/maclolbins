"""Command-line entry point: `lolbins scan` and `lolbins render`."""

import argparse
import sys
from pathlib import Path

from lolbins.catalog import CatalogError, load_catalog
from lolbins.probe import ProbeError, parallels_command, run_probe
from lolbins.scan import (
    DEFAULT_SCAN_DIRS,
    ScanFileError,
    build_scan,
    load_scan,
    rejoin_catalog,
    save_scan,
)
from lolbins.site import render_site


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        return _render(args)
    except (CatalogError, ProbeError, ScanFileError) as exc:
        print(f"lolbins: error: {exc}", file=sys.stderr)
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lolbins", description="Enumerate living-off-the-land binaries on a macOS VM."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser(
        "scan", help="probe a Parallels VM and write scan.json plus report.html"
    )
    scan.add_argument("--vm", required=True, help="Parallels VM name or UUID (see prlctl list)")
    scan.add_argument(
        "--out", type=Path, default=Path("reports"), help="parent directory for scan output"
    )
    scan.add_argument("--catalog", type=Path, help="catalog TOML (default: packaged catalog)")
    scan.add_argument(
        "--timeout", type=float, default=900, help="seconds to wait for the probe (default 900)"
    )

    render = commands.add_parser("render", help="re-render the site from a saved scan.json")
    render.add_argument("scan_json", type=Path)
    render.add_argument(
        "-o", "--output", type=Path, help="site directory (default: beside scan.json)"
    )
    render.add_argument("--catalog", type=Path, help="catalog TOML (default: packaged catalog)")
    return parser


def _scan(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    scan_dirs = list(DEFAULT_SCAN_DIRS)
    print(f"Probing {args.vm} ({len(catalog.entries)} catalog entries)…", file=sys.stderr)
    probe = run_probe(parallels_command(args.vm), scan_dirs, catalog.all_paths(), args.timeout)
    scan = build_scan(catalog, probe, target=args.vm, scan_dirs=scan_dirs)

    stamp = scan["facts"].get("collected_at", "unknown").replace(":", "").replace("-", "")
    out_dir = args.out / f"{_safe_name(args.vm)}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=False)
    save_scan(scan, out_dir / "scan.json")
    index = render_site(scan, out_dir)

    present = sum(1 for entry in scan["entries"] if entry["status"] == "present")
    print(
        f"{present}/{len(scan['entries'])} catalogued LOLBins present, "
        f"{len(scan['inventory'])} binaries inventoried",
        file=sys.stderr,
    )
    print(index)
    return 0


def _render(args: argparse.Namespace) -> int:
    scan = rejoin_catalog(load_scan(args.scan_json), load_catalog(args.catalog))
    out_dir = args.output or args.scan_json.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    print(render_site(scan, out_dir))
    return 0


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
