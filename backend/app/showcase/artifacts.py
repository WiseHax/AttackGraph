"""Write the showcase artifacts to a directory.

Only four fixed filenames are ever written, with LF line endings and UTF-8,
so the same report produces byte-identical files on every platform. Nothing
is deleted. Writing through a symlink, or into a path that exists but is not
a directory, is refused.
"""

from pathlib import Path

from app.showcase.render import render_html, render_markdown
from app.showcase.report import ShowcaseReport
from app.showcase.svg import render_svg

ARTIFACT_FILENAMES = ("showcase.json", "report.md", "report.html", "graph.svg")


class ArtifactWriteError(RuntimeError):
    """The output location is not safe to write to."""


def render_artifacts(report: ShowcaseReport) -> dict[str, str]:
    """The artifact contents, keyed by filename."""
    return {
        "showcase.json": report.model_dump_json(indent=2) + "\n",
        "report.md": render_markdown(report),
        "report.html": render_html(report),
        "graph.svg": render_svg(report),
    }


def write_artifacts(report: ShowcaseReport, output_dir: Path) -> list[Path]:
    output_dir = Path(output_dir)
    if output_dir.is_symlink():
        raise ArtifactWriteError(f"refusing to write into a symlinked directory: {output_dir}")
    if output_dir.exists() and not output_dir.is_dir():
        raise ArtifactWriteError(f"output path exists and is not a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    contents = render_artifacts(report)
    targets = [output_dir / name for name in ARTIFACT_FILENAMES]
    for target in targets:
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ArtifactWriteError(f"refusing to overwrite a non-regular file: {target}")
    for target in targets:
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents[target.name])
    return targets
