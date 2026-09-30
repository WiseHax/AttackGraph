"""Tests for the showcase renderers and artifact writer (no database).

The committed example result (docs/showcase/showcase.json) is the input: the
renderers are pure functions of a ShowcaseReport, so rendering it must
reproduce the committed Markdown, HTML and SVG exactly.

Categories:
- Determinism: rendering is byte-stable and matches the committed artifacts.
- Security (SEC-8): text from the report is escaped in every format.
- Invariant: the artifact writer writes only its fixed files, with LF endings,
  and refuses unsafe targets; the showcase layer sits above everything else
  and imports no network libraries.
"""

import ast
from pathlib import Path

import pytest

from app.showcase.artifacts import ARTIFACT_FILENAMES, ArtifactWriteError, render_artifacts, write_artifacts
from app.showcase.render import render_html, render_markdown
from app.showcase.report import ShowcaseReport
from app.showcase.svg import render_svg

BACKEND_DIR = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = BACKEND_DIR.parent / "docs" / "showcase"
HOSTILE = '<script>alert("x")</script> | `rm` **bold** [link](http://example.test) & "quote"'


@pytest.fixture(scope="module")
def committed_report() -> ShowcaseReport:
    return ShowcaseReport.model_validate_json((EXAMPLES_DIR / "showcase.json").read_text(encoding="utf-8"))


def _committed(name: str) -> str:
    return (EXAMPLES_DIR / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def test_rendering_the_committed_result_reproduces_the_committed_artifacts(committed_report):
    for name, content in render_artifacts(committed_report).items():
        assert content == _committed(name), f"docs/showcase/{name} is stale"


def test_rendering_is_deterministic(committed_report):
    assert render_artifacts(committed_report) == render_artifacts(committed_report)


def _hostile(report: ShowcaseReport) -> ShowcaseReport:
    first = report.environment.entities[0]
    entities = [first.model_copy(update={"name": HOSTILE, "description": HOSTILE})] + \
        list(report.environment.entities[1:])
    environment = report.environment.model_copy(update={"entities": entities, "organisation": HOSTILE})
    return report.model_copy(update={"environment": environment})


def test_report_text_is_escaped_in_html_and_svg(committed_report):
    hostile = _hostile(committed_report)
    for output in (render_html(hostile), render_svg(hostile)):
        assert "<script" not in output
        assert "&lt;script&gt;" in output


def test_report_text_is_escaped_in_markdown(committed_report):
    markdown = render_markdown(_hostile(committed_report))
    assert "<script>" not in markdown
    assert "[link](http" not in markdown
    assert "\\<script\\>" in markdown


def test_html_report_is_self_contained(committed_report):
    html = render_html(committed_report)
    assert "<script" not in html
    assert "http://" not in html.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "https://" not in html
    assert "<svg" in html


def test_write_artifacts_writes_exactly_the_fixed_files_with_lf(committed_report, tmp_path):
    written = write_artifacts(committed_report, tmp_path / "out")
    assert sorted(p.name for p in written) == sorted(ARTIFACT_FILENAMES)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(ARTIFACT_FILENAMES)
    for path in written:
        assert b"\r\n" not in path.read_bytes()
        assert path.read_text(encoding="utf-8") == render_artifacts(committed_report)[path.name]


def test_write_artifacts_refuses_a_file_as_output_directory(committed_report, tmp_path):
    target = tmp_path / "not-a-directory"
    target.write_text("keep me")
    with pytest.raises(ArtifactWriteError, match="not a directory"):
        write_artifacts(committed_report, target)
    assert target.read_text() == "keep me"


def test_write_artifacts_refuses_symlinked_targets(committed_report, tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "report.md" or real_is_symlink(self))
    with pytest.raises(ArtifactWriteError, match="non-regular file"):
        write_artifacts(committed_report, output)
    assert list(output.iterdir()) == []


def _imports(path: Path) -> set[str]:
    modules = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_no_lower_layer_imports_the_showcase():
    for layer in ("domain", "storage", "graph", "analytics", "schemas", "security"):
        for path in (BACKEND_DIR / "app" / layer).rglob("*.py"):
            assert not any(m.startswith("app.showcase") for m in _imports(path)), path


def test_showcase_imports_no_network_libraries():
    network = ("socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp", "smtplib", "ftplib")
    for path in (BACKEND_DIR / "app" / "showcase").rglob("*.py"):
        for module in _imports(path):
            assert module.split(".")[0] not in network, (path, module)
