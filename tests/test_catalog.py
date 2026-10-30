from pathlib import Path

import pytest

from maclolbins.catalog import CatalogError, load_catalog

TECHNIQUES = """
[meta]
version = "test"

[techniques]
"T1059" = { name = "Command and Scripting Interpreter", tactics = ["Execution"] }
"T1105" = { name = "Ingress Tool Transfer", tactics = ["Command and Control"] }
"""

GOOD_ENTRY = """
[[binary]]
name = "curl"
paths = ["/usr/bin/curl"]
techniques = ["T1105", "T1059"]
privilege = "user"
abuse = "downloads"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "catalog.toml"
    path.write_text(text)
    return path


def test_packaged_catalog_is_valid():
    catalog = load_catalog()
    assert len(catalog.entries) >= 50
    assert all(path.startswith("/") for path in catalog.all_paths())


def test_packaged_socketfilterfw_documents_xpc_functionality():
    entries = {entry.name: entry for entry in load_catalog().entries}
    assert entries["socketfilterfw"].xpc_functionality is not None
    assert "Application Firewall" in entries["socketfilterfw"].xpc_functionality


def test_tactics_are_derived_from_techniques(tmp_path):
    catalog = load_catalog(write(tmp_path, TECHNIQUES + GOOD_ENTRY))
    assert catalog.tactics_for(catalog.entries[0]) == ["Command and Control", "Execution"]


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (GOOD_ENTRY.replace('"T1105", ', ""), "never used"),
        (GOOD_ENTRY.replace('"T1059"', '"T9999"'), "unknown techniques"),
        (GOOD_ENTRY.replace('"/usr/bin/curl"', '"usr/bin/curl"'), "must be absolute"),
        (GOOD_ENTRY.replace('["/usr/bin/curl"]', "[]"), "non-empty list"),
        (GOOD_ENTRY.replace('"user"', '"admin"'), "privilege must be one of"),
        (GOOD_ENTRY.replace('abuse = "downloads"', ""), "abuse is required"),
        (
            GOOD_ENTRY.replace(
                'abuse = "downloads"', 'abuse = "downloads"\nxpc_functionality = ""'
            ),
            "xpc_functionality must be a non-empty string",
        ),
        (GOOD_ENTRY + GOOD_ENTRY, "duplicate binary names"),
        (
            GOOD_ENTRY + GOOD_ENTRY.replace('name = "curl"', 'name = "curl2"'),
            "listed by both",
        ),
    ],
)
def test_invalid_entries_are_rejected(tmp_path, entry, message):
    with pytest.raises(CatalogError, match=message):
        load_catalog(write(tmp_path, TECHNIQUES + entry))


def test_empty_catalog_is_rejected(tmp_path):
    with pytest.raises(CatalogError, match="no \\[\\[binary\\]\\] entries"):
        load_catalog(write(tmp_path, TECHNIQUES))


def test_invalid_toml_names_the_file(tmp_path):
    path = write(tmp_path, "[meta\n")
    with pytest.raises(CatalogError, match="invalid TOML"):
        load_catalog(path)


EXAMPLE = """
[[binary.example]]
title = "Fetch a file"
command = "curl -O https://host/p"
explanation = "downloads a file"
"""


def test_examples_are_parsed(tmp_path):
    catalog = load_catalog(write(tmp_path, TECHNIQUES + GOOD_ENTRY + EXAMPLE))
    (example,) = catalog.entries[0].examples
    assert example.title == "Fetch a file"
    assert example.command == "curl -O https://host/p"
    assert example.privilege == "user"


def test_example_privilege_is_validated(tmp_path):
    bad = EXAMPLE + 'privilege = "admin"\n'
    with pytest.raises(CatalogError, match="privilege must be one of"):
        load_catalog(write(tmp_path, TECHNIQUES + GOOD_ENTRY + bad))


@pytest.mark.parametrize("field", ["title", "command", "explanation"])
def test_example_requires_each_field(tmp_path, field):
    bad = "\n".join(line for line in EXAMPLE.splitlines() if not line.startswith(f"{field} = "))
    with pytest.raises(CatalogError, match=f"non-empty {field}"):
        load_catalog(write(tmp_path, TECHNIQUES + GOOD_ENTRY + bad))


def test_packaged_catalog_entries_all_have_examples():
    catalog = load_catalog()
    assert all(entry.examples for entry in catalog.entries)


def test_vm_validated_examples_avoid_macos_command_parser_traps():
    entries = {entry.name: entry for entry in load_catalog().entries}
    tftp = entries["tftp"].examples[0].command
    assert " -c " not in tftp  # Apple's tftp is interactive; -c is not supported.
    assert "| tftp host.example" in tftp

    assert all(example.command.startswith("/usr/bin/log ") for example in entries["log"].examples)
    assert all("Ethernet" in example.command for example in entries["networksetup"].examples)
