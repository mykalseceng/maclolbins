"""Compare what the MCP server returns with what a rendered report shows, field by field.

The report's data is assets/data.js, which index.html reads. Every binary in it must come back
from list_lolbins, and get_lolbin must say exactly what the report says about it.
"""

import json
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.server.mcpserver import MCPServer

# Mirrors TCC_GRANT_KEYS in browser.html, independently of maclolbins.views.
TCC_GRANT_KEYS = {"com.apple.private.tcc.allow", "com.apple.private.tcc.allow.overridable"}


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
    problems: list[str] = []
    async with Client(server) as client:
        listed = await client.call_tool("list_lolbins", {"scan_id": scan_id})
        assert listed.structured_content is not None, listed.content
        listed_rows = listed.structured_content["result"]
        rows = {row["path"]: row for row in listed_rows}
        report_paths = [file["path"] for file in data["inventory"]]
        if sorted(rows) != sorted(report_paths):
            problems.append(f"list_lolbins paths differ: {sorted(set(rows) ^ set(report_paths))}")
        by_score = sorted(data["inventory"], key=lambda f: (-f["score"], f["path"]))
        if [row["path"] for row in listed_rows] != [f["path"] for f in by_score]:
            problems.append("list_lolbins is not in the report's evidence-score order")
        for file in data["inventory"]:
            result = await client.call_tool(
                "get_lolbin", {"scan_id": scan_id, "binary": file["path"]}
            )
            if result.is_error or result.structured_content is None:
                problems.append(f"{file['path']}: {result.content}")
                continue
            detail = result.structured_content
            expected = _expected_detail(file, data)
            problems.extend(
                f"{file['path']}: {key} is {detail.get(key)!r}, report has {value!r}"
                for key, value in expected.items()
                if detail.get(key) != value
            )
            row = rows.get(file["path"])
            if row and (row["flags"], row["score"]) != (file["flags"], file["score"]):
                problems.append(f"{file['path']}: list_lolbins flags or score differ")
    return problems


def _technique(t: dict[str, Any]) -> dict[str, Any]:
    url = f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/', 1)}/"
    return {"id": t["id"], "name": t["name"], "url": url}


def _expected_detail(file: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    explanations = data["entitlements"]
    note = data["notes"][file["note"]] if file["note"] else None
    return {
        "path": file["path"],
        "name": file["path"].rsplit("/", 1)[-1],
        "description": file["summary"],
        "score": file["score"],
        "capabilities": [
            {
                "id": match["id"],
                "title": data["capabilities"][match["id"]]["title"],
                "summary": data["capabilities"][match["id"]]["summary"],
                "evidence": match["evidence"],
                "techniques": [
                    _technique(t) for t in data["capabilities"][match["id"]]["techniques"]
                ],
            }
            for match in file["capabilities"]
        ],
        "abuse": note["abuse"] if note else None,
        "privilege": file["privilege"],
        "tactics": file["tactics"],
        "techniques": [_technique(t) for t in file["techniques"]],
        "examples": note["examples"] if note else [],
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
                    if key in TCC_GRANT_KEYS and isinstance(s, str)
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
