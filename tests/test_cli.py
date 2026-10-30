from pathlib import Path

from conftest import f_record, probe_text

from maclolbins import cli
from maclolbins.catalog import load_catalog
from maclolbins.probe import ProbeError, parse_output
from maclolbins.scan import load_scan


def test_scan_writes_json_and_html(tmp_path: Path, monkeypatch, capsys):
    def fake_run_probe(command, scan_dirs, extra_paths, timeout):
        assert command[:3] == ["prlctl", "exec", "my vm"]
        assert "/usr/bin/curl" in extra_paths
        return parse_output(probe_text(f_record("/usr/bin/curl")))

    monkeypatch.setattr(cli, "run_probe", fake_run_probe)
    assert cli.main(["scan", "--vm", "my vm", "--out", str(tmp_path)]) == 0

    out_dir = tmp_path / "my_vm-20261026T170000Z"
    assert (out_dir / "scan.json").is_file()
    assert (out_dir / "index.html").is_file()
    assert (out_dir / "assets" / "data.js").is_file()
    assert '"/usr/bin/curl"' in (out_dir / "assets" / "data.js").read_text()
    assert capsys.readouterr().out.strip() == str(out_dir / "index.html")
    assert len(load_scan(out_dir / "scan.json")["entries"]) == len(load_catalog().entries)

    rendered = tmp_path / "again"
    assert cli.main(["render", str(out_dir / "scan.json"), "-o", str(rendered)]) == 0
    assert (rendered / "index.html").read_text() == (out_dir / "index.html").read_text()
    assert (rendered / "assets" / "data.js").read_text() == (
        out_dir / "assets" / "data.js"
    ).read_text()


def test_probe_errors_become_exit_code_1(tmp_path: Path, monkeypatch, capsys):
    def failing_run_probe(*_args, **_kwargs):
        raise ProbeError("VM not running")

    monkeypatch.setattr(cli, "run_probe", failing_run_probe)
    assert cli.main(["scan", "--vm", "macOS", "--out", str(tmp_path)]) == 1
    assert "maclolbins: error: VM not running" in capsys.readouterr().err


def test_render_reports_unreadable_scan(tmp_path: Path, capsys):
    assert cli.main(["render", str(tmp_path / "missing.json")]) == 1
    assert "cannot read scan file" in capsys.readouterr().err
