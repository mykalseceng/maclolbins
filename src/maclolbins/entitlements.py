"""Explain entitlement keys against Apple's own entitlement documentation.

Apple's entitlement reference at developer.apple.com/documentation/bundleresources/entitlements
is the source of truth (scraped by scripts/update_apple_entitlements.py). A key listed there is
documented: it gets Apple's own description and a link to its Apple page. A key that is not
listed is undocumented, by definition, and carries no off-site link; the key's namespace still
gives a factual hint of what family it belongs to.
"""

import json
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

APPLE_DOCS_INDEX = "https://developer.apple.com/documentation/bundleresources/entitlements"

# (key prefix, namespace label, what holding any key in this namespace means)
NAMESPACES: tuple[tuple[str, str, str], ...] = (
    (
        "com.apple.private.tcc.",
        "Private TCC",
        "Reaches privacy-protected data, or manages the grants themselves, without the usual "
        "consent prompt.",
    ),
    (
        "com.apple.rootless.",
        "SIP (rootless)",
        "Acts on filesystem locations and processes that System Integrity Protection restricts; "
        "the .heritable variants pass that right to child processes.",
    ),
    (
        "com.apple.private.security.",
        "Private security",
        "Opts out of a sandbox, container or storage restriction that applies to ordinary code.",
    ),
    (
        "com.apple.system-task-ports",
        "Task ports",
        "Obtains the task port of another process, which allows reading and writing its memory.",
    ),
    (
        "com.apple.private.",
        "Private",
        "An Apple-internal entitlement. The service that checks the key defines what it grants.",
    ),
    (
        "com.apple.security.cs.",
        "Hardened runtime",
        "Relaxes one of the hardened runtime's protections, such as library validation or "
        "DYLD environment variables.",
    ),
    (
        "com.apple.security.",
        "App Sandbox / code signing",
        "Grants a sandboxed resource, such as network access, a device or a user data store.",
    ),
    (
        "com.apple.developer.",
        "Developer capability",
        "A capability an app opts into, such as HealthKit, iCloud or Network Extension.",
    ),
)


# Entitlements that switch off a code-signing protection when set to true. Holding one makes a
# binary a host for injected code or a debugger target, whatever its other protections.
RUNTIME_WEAKENERS: dict[str, str] = {
    "com.apple.security.get-task-allow": "Lets other processes take its task port, as a debugger "
    "does, and read or write its memory.",
    "get-task-allow": "Lets other processes take its task port, as a debugger does, and read or "
    "write its memory.",
    "com.apple.security.cs.disable-library-validation": "Loads libraries and plug-ins signed by "
    "anyone, so a planted dylib runs inside it.",
    "com.apple.private.security.clear-library-validation": "Can turn library validation off for "
    "itself at run time, then load unsigned code.",
    "com.apple.security.cs.allow-dyld-environment-variables": "Honours DYLD_* variables such as "
    "DYLD_INSERT_LIBRARIES, so a launcher can inject a library.",
    "com.apple.security.cs.allow-unsigned-executable-memory": "May create writable and executable "
    "memory without signing it, so injected shellcode can run.",
    "com.apple.security.cs.disable-executable-page-protection": "Turns off executable memory "
    "protection entirely, the broadest of the runtime exceptions.",
}


def runtime_weakeners(entitlements: dict[str, Any]) -> list[str]:
    """Return the protection-weakening entitlements a binary holds with the value true."""
    return [key for key in RUNTIME_WEAKENERS if entitlements.get(key) is True]


@dataclass(frozen=True)
class Explanation:
    """What one entitlement key means, and where to read more."""

    key: str
    title: str
    summary: str
    namespace: str
    url: str
    documented: bool


@cache
def _apple_docs() -> dict[str, dict[str, str]]:
    text = (
        resources.files("maclolbins")
        .joinpath("apple_entitlements.json")
        .read_text(encoding="utf-8")
    )
    docs: dict[str, dict[str, str]] = json.loads(text)
    return docs


def explain(key: str) -> Explanation:
    """Return the documentation or namespace meaning for one entitlement key.

    Args:
        key: The entitlement key exactly as it appears in the code signature.

    Returns:
        An explanation; `documented` is True when Apple publishes a page for the key.
    """
    documented = _apple_docs().get(key.lower())
    namespace, meaning = _namespace(key)
    if documented:
        return Explanation(
            key=key,
            title=documented["title"],
            summary=documented["abstract"] or meaning,
            namespace=namespace,
            url=documented["url"],
            documented=True,
        )
    return Explanation(
        key=key,
        title=key,
        summary=meaning,
        namespace=namespace,
        url="",
        documented=False,
    )


def _namespace(key: str) -> tuple[str, str]:
    for prefix, label, meaning in NAMESPACES:
        if key.startswith(prefix):
            return label, meaning
    return "Other", "No Apple documentation and no known namespace; check the signing identifier."
