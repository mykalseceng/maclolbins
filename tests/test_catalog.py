from pathlib import Path

import pytest

from maclolbins.catalog import CatalogError, library_names, load_catalog

TECHNIQUES = """
[meta]
version = "test"

[techniques]
"T1059" = { name = "Command and Scripting Interpreter", tactics = ["Execution"] }
"T1105" = { name = "Ingress Tool Transfer", tactics = ["Command and Control"] }
"""

GOOD_CAPABILITY = """
[[capability]]
id = "fetches-urls"
title = "Makes HTTP requests"
summary = "Uses libcurl."
techniques = ["T1105"]
symbols = ["_curl_easy_perform"]
libraries = ["libcurl"]
"""

GOOD_NOTE = """
[[note]]
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
    assert len(catalog.capabilities) >= 20
    assert "_curl_easy_perform" in catalog.all_symbols()
    assert all(path.startswith("/") for note in catalog.notes for path in note.paths)


def test_tactics_are_derived_from_techniques(tmp_path):
    catalog = load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + GOOD_NOTE))
    assert catalog.tactics_for(catalog.notes[0].techniques) == ["Command and Control", "Execution"]


def test_capability_evidence_matches_symbols_and_library_names(tmp_path):
    (cap,) = load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + GOOD_NOTE)).capabilities
    symbols = ["_curl_easy_perform", "_printf"]
    library_paths = ["/usr/lib/libcurl.4.dylib", "/usr/lib/libSystem.B.dylib"]
    found = cap.evidence(symbols, library_paths)
    assert found == ["/usr/lib/libcurl.4.dylib", "_curl_easy_perform"]
    assert cap.evidence(["_printf"], ["/usr/lib/libcurlish.dylib"]) == []


@pytest.mark.parametrize(
    ("path", "names"),
    [
        ("/usr/lib/libcurl.4.dylib", {"libcurl"}),
        ("/usr/lib/libSystem.B.dylib", {"libSystem"}),
        ("/System/Library/Frameworks/Tcl.framework/Versions/8.5/Tcl", {"Tcl"}),
        ("/System/Library/PrivateFrameworks/TCC.framework/Versions/A/TCC", {"TCC"}),
        ("/System/Library/Perl/5.34/darwin-thread-multi-2level/CORE/libperl.dylib", {"libperl"}),
        (
            "/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/lib/libruby.2.6.dylib",
            {"Ruby", "libruby"},
        ),
    ],
)
def test_library_names_drop_directories_and_versions(path, names):
    assert library_names(path) == names


def test_a_dylib_inside_a_framework_matches_by_its_own_name(tmp_path):
    capability = GOOD_CAPABILITY.replace('libraries = ["libcurl"]', 'libraries = ["libruby"]')
    (cap,) = load_catalog(write(tmp_path, TECHNIQUES + capability + GOOD_NOTE)).capabilities
    ruby = "/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/lib/libruby.2.6.dylib"
    assert cap.evidence([], [ruby]) == [ruby]


def test_note_for_finds_the_note_by_path(tmp_path):
    catalog = load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + GOOD_NOTE))
    note = catalog.note_for("/usr/bin/curl")
    assert note is not None
    assert note.name == "curl"
    assert catalog.note_for("/usr/bin/true") is None


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (GOOD_NOTE.replace('"T1059"', '"T9999"'), "unknown techniques"),
        (GOOD_NOTE.replace('"/usr/bin/curl"', '"usr/bin/curl"'), "must be absolute"),
        (GOOD_NOTE.replace('["/usr/bin/curl"]', "[]"), "non-empty list"),
        (GOOD_NOTE.replace('"user"', '"admin"'), "privilege must be one of"),
        (GOOD_NOTE.replace('abuse = "downloads"', ""), "abuse is required"),
        (GOOD_NOTE + GOOD_NOTE, "duplicate note names"),
        (GOOD_NOTE + GOOD_NOTE.replace('name = "curl"', 'name = "curl2"'), "in both note"),
        (GOOD_NOTE.replace(', "T1059"', ""), "never used"),
    ],
)
def test_invalid_notes_are_rejected(tmp_path, body, message):
    with pytest.raises(CatalogError, match=message):
        load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + body))


@pytest.mark.parametrize(
    ("capability", "message"),
    [
        (GOOD_CAPABILITY.replace('"fetches-urls"', '"Fetches URLs"'), "lowercase-kebab-case"),
        (GOOD_CAPABILITY.replace('title = "Makes HTTP requests"', ""), "title is required"),
        (GOOD_CAPABILITY.replace('summary = "Uses libcurl."', 'summary = " "'), "summary is"),
        (GOOD_CAPABILITY.replace('"_curl_easy_perform"', '"two words"'), "must be one token"),
        (GOOD_CAPABILITY.replace('symbols = ["_curl_easy_perform"]', 'symbols = "x"'), "a list"),
        (
            GOOD_CAPABILITY.replace('symbols = ["_curl_easy_perform"]', "").replace(
                'libraries = ["libcurl"]', ""
            ),
            "needs symbols, libraries or both",
        ),
        (GOOD_CAPABILITY.replace('["T1105"]', "[]"), "techniques must be a non-empty list"),
        (GOOD_CAPABILITY + GOOD_CAPABILITY, "duplicate capability ids"),
    ],
)
def test_invalid_capabilities_are_rejected(tmp_path, capability, message):
    with pytest.raises(CatalogError, match=message):
        load_catalog(write(tmp_path, TECHNIQUES + capability + GOOD_NOTE))


def test_catalog_without_capabilities_is_rejected(tmp_path):
    with pytest.raises(CatalogError, match="no \\[\\[capability\\]\\] rules"):
        load_catalog(write(tmp_path, TECHNIQUES + GOOD_NOTE))


def test_notes_are_optional(tmp_path):
    techniques = TECHNIQUES.replace(
        '"T1059" = { name = "Command and Scripting Interpreter", tactics = ["Execution"] }\n', ""
    )
    catalog = load_catalog(write(tmp_path, techniques + GOOD_CAPABILITY))
    assert catalog.notes == ()


def test_invalid_toml_names_the_file(tmp_path):
    path = write(tmp_path, "[meta\n")
    with pytest.raises(CatalogError, match="invalid TOML"):
        load_catalog(path)


EXAMPLE = """
[[note.example]]
title = "Fetch a file"
command = "curl -O https://host/p"
explanation = "downloads a file"
"""


def test_examples_are_parsed(tmp_path):
    catalog = load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + GOOD_NOTE + EXAMPLE))
    (example,) = catalog.notes[0].examples
    assert example.title == "Fetch a file"
    assert example.command == "curl -O https://host/p"
    assert example.privilege == "user"


def test_example_privilege_is_validated(tmp_path):
    bad = EXAMPLE + 'privilege = "admin"\n'
    with pytest.raises(CatalogError, match="privilege must be one of"):
        load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + GOOD_NOTE + bad))


@pytest.mark.parametrize("field", ["title", "command", "explanation"])
def test_example_requires_each_field(tmp_path, field):
    bad = "\n".join(line for line in EXAMPLE.splitlines() if not line.startswith(f"{field} = "))
    with pytest.raises(CatalogError, match=f"non-empty {field}"):
        load_catalog(write(tmp_path, TECHNIQUES + GOOD_CAPABILITY + GOOD_NOTE + bad))


def test_packaged_notes_all_have_examples():
    assert all(note.examples for note in load_catalog().notes)


def test_packaged_notes_only_cover_default_path_directories():
    path_dirs = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/System/Cryptexes/App/usr/bin"}
    for note in load_catalog().notes:
        for path in note.paths:
            assert path.rsplit("/", 1)[0] in path_dirs, path


def test_vm_validated_examples_avoid_macos_command_parser_traps():
    notes = {note.name: note for note in load_catalog().notes}
    tftp = notes["tftp"].examples[0].command
    assert " -c " not in tftp  # Apple's tftp is interactive; -c is not supported.
    assert "| tftp host.example" in tftp

    assert all(example.command.startswith("/usr/bin/log ") for example in notes["log"].examples)
    assert all("Ethernet" in example.command for example in notes["networksetup"].examples)
