"""Refresh src/maclolbins/apple_entitlements.json from Apple's developer documentation.

Apple publishes its documentation as JSON. This walks the Entitlements index plus the
collection pages it links to (Hardened Runtime, App Sandbox, ...) and records every
documented entitlement's title, page URL and one-line abstract, keyed by the lowercased
entitlement key (Apple's page slug).

Run with: uv run python scripts/update_apple_entitlements.py
"""

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

DOCS = "https://developer.apple.com"
DATA = f"{DOCS}/tutorials/data"
INDEX = "/documentation/bundleresources/entitlements"
ENTITLEMENT_PREFIX = f"{INDEX}/"
OUTPUT = Path(__file__).resolve().parent.parent / "src" / "maclolbins" / "apple_entitlements.json"


def fetch(path: str) -> dict[str, Any]:
    """Fetch one documentation page as JSON."""
    url = f"{DATA}{path}.json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 (fixed https host)
        return json.load(response)


def collect(page: dict[str, Any], found: dict[str, dict[str, str]]) -> list[str]:
    """Record entitlement symbols referenced by a page; return its collection links."""
    collections = []
    for ref in page.get("references", {}).values():
        url = ref.get("url", "")
        if ref.get("role") == "symbol" and url.startswith(ENTITLEMENT_PREFIX):
            slug = url.removeprefix(ENTITLEMENT_PREFIX)
            abstract = "".join(part.get("text", "") for part in ref.get("abstract", []))
            found[slug] = {"title": ref.get("title", slug), "url": DOCS + url, "abstract": abstract}
        elif ref.get("role") in ("collectionGroup", "collection") and url.startswith(
            ("/documentation/bundleresources/", "/documentation/security/")
        ):
            collections.append(url)
    return collections


def main() -> int:
    """Crawl the index and its collections, then write the JSON file."""
    found: dict[str, dict[str, str]] = {}
    queue = collect(fetch(INDEX), found)
    seen = {INDEX}
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        queue.extend(collect(fetch(path), found))
    OUTPUT.write_text(json.dumps(dict(sorted(found.items())), indent=1) + "\n", encoding="utf-8")
    print(
        f"{len(found)} documented entitlements from {len(seen)} pages -> {OUTPUT}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
