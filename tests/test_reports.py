from pathlib import Path

import pytest
from conftest import f_record, probe_text

from maclolbins.catalog import load_catalog
from maclolbins.probe import parse_output
from maclolbins.reports import safe_name, scan_ids, scan_path, write_report
from maclolbins.scan import DEFAULT_SCAN_DIRS, ScanFileError, build_scan, load_scan


def make_scan(target: str):
    probe = parse_output(probe_text(f_record("/usr/bin/curl")))
    return build_scan(load_catalog(), probe, target, list(DEFAULT_SCAN_DIRS))


def test_write_report_names_the_directory_by_scan_id(tmp_path: Path):
    out_dir = write_report(make_scan("my vm"), tmp_path / "reports")
    assert out_dir.name == "my_vm-20261026T170000Z"
    assert (out_dir / "index.html").is_file()
    assert scan_ids(tmp_path / "reports") == [out_dir.name]
    assert load_scan(scan_path(tmp_path / "reports", out_dir.name))["target"] == "my vm"


def test_write_report_refuses_to_overwrite(tmp_path: Path):
    write_report(make_scan("vm"), tmp_path)
    with pytest.raises(FileExistsError):
        write_report(make_scan("vm"), tmp_path)


@pytest.mark.parametrize(
    ("name", "expected"),
    [("../..", "target"), (".hidden", "hidden"), ("", "target"), ("a/b", "a_b")],
)
def test_safe_name_stays_inside_the_reports_directory(name, expected):
    assert safe_name(name) == expected


def test_scan_ids_skip_directories_without_a_scan(tmp_path: Path):
    (tmp_path / "empty").mkdir()
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "scan.json").write_text("{}")
    assert scan_ids(tmp_path) == []
    assert scan_ids(tmp_path / "missing") == []


@pytest.mark.parametrize("scan_id", ["../x", "a/b", "", "nope"])
def test_scan_path_rejects_bad_or_unknown_ids(tmp_path: Path, scan_id):
    with pytest.raises(ScanFileError):
        scan_path(tmp_path, scan_id)
