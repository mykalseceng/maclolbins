"""Compare what the MCP server returns with what a rendered report shows, field by field.

The report's data is assets/data.js, which index.html reads. Every binary in it must come back
from list_lolbins, and get_lolbin must say exactly what the report says about it.
"""

import json
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.server.mcpserver import MCPServer


def report_data(report_dir: Path) -> dict[str, Any]:
    """Read window.LOLBINS from a rendered report."""
    text = (report_dir / "assets" / "data.js").read_text(encoding="utf-8")
    prefix, suffix = "window.LOLBINS = ", ";\n"
    assert text.startswith(prefix)
    assert text.endswith(suffix)
    return json.loads(text[len(prefix) : -len(suffix)])


async def mismatches(server: MCPServer, scan_id: str, report_dir: Path) -> list[str]:
    """Return every difference between the server's answers and the report; empty means none."""
    data = report_data(report_dir)
    entries = {entry["name"]: entry for entry in data["entries"]}
    problems: list[str] = []
    async with Client(server) as client:
        listed = await client.call_tool("list_lolbins", {"scan_id": scan_id})
        assert listed.structured_content is not None, listed.content
        rows = {row["path"]: row for row in listed.structured_content["result"]}
        report_paths = [file["path"] for file in data["inventory"]]
        if sorted(rows) != sorted(report_paths):
            problems.append(f"list_lolbins paths differ: {sorted(set(rows) ^ set(report_paths))}")
        for file in data["inventory"]:
            result = await client.call_tool(
                "get_lolbin", {"scan_id": scan_id, "binary": file["path"]}
            )
            if result.is_error or result.structured_content is None:
                problems.append(f"{file['path']}: {result.content}")
                continue
            detail = result.structured_content
            expected = _expected_detail(file, entries[file["entry"]], data)
            problems.extend(
                f"{file['path']}: {key} is {detail.get(key)!r}, report has {value!r}"
                for key, value in expected.items()
                if detail.get(key) != value
            )
            if file["path"] in rows and rows[file["path"]]["flags"] != file["flags"]:
                problems.append(f"{file['path']}: list_lolbins flags differ from the report")
    return problems


def _expected_detail(
    file: dict[str, Any], entry: dict[str, Any], data: dict[str, Any]
) -> dict[str, Any]:
    explanations = data["entitlements"]
    return {
        "path": file["path"],
        "name": entry["name"],
        "description": file["summary"] or entry["description"],
        "abuse": entry["abuse"],
        "privilege": entry["privilege"],
        "tactics": entry["tactics"],
        "techniques": [
            {
                "id": t["id"],
                "name": t["name"],
                "url": f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/', 1)}/",
            }
            for t in entry["techniques"]
        ],
        "examples": entry["examples"],
        "xpc_functionality": entry["xpc_functionality"],
        "flags": file["flags"],
        "file": {
            "link_target": file["link"],
            "owner": file["owner"],
            "perms": file["perms"],
            "size": file["size"],
            "sha256": file["sha256"],
            "bsd_flags": file["bsd_flags"],
            "sip_protected": "restricted" in file["bsd_flags"],
        },
        "signing": file["signing"],
        "hardened_runtime": "runtime" in file["signing"]["flags"],
        "entitlements": [
            {
                "key": key,
                "title": explanations[key]["title"],
                "summary": explanations[key]["summary"],
                "namespace": explanations[key]["namespace"],
                "documented": explanations[key]["documented"],
                "apple_docs_url": explanations[key]["url"] or None,
                "weakens_runtime": data["runtime_weakeners"].get(key) if value is True else None,
                "value": value,
                "tcc_services": [
                    {"service": s, "label": data["tcc_labels"].get(s, s)}
                    for s in (value if isinstance(value, list) else [])
                    if key.startswith("com.apple.private.tcc.allow") and isinstance(s, str)
                ],
            }
            for key, value in sorted(file["entitlements"].items())
        ],
        "tcc_grants": [
            {**grant, "service_label": data["tcc_labels"].get(grant["service"], grant["service"])}
            for grant in file["tcc"]
        ],
        "xpc": file["xpc"],
    }
