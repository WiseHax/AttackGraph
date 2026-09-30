"""Run the AttackGraph showcase: `python -m app.showcase`.

Requires an empty PostgreSQL database migrated to the Alembic head (the
project's standard development database after `alembic upgrade head`). The
synthetic environment is loaded in a transaction that is always rolled back;
only the artifact files are written.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from app.analytics.engine_identity import EngineIdentityService
from app.showcase.artifacts import ArtifactWriteError, write_artifacts
from app.showcase.pipeline import ShowcaseConsistencyError, ShowcaseDatabaseNotReady, run_showcase

_DEFAULT_ENGINE_METADATA = "/app/engine_metadata.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.showcase",
        description=(
            "Run the AttackGraph showcase: load a deterministic synthetic environment into an empty, "
            "migrated PostgreSQL database inside a transaction that is always rolled back, run the real "
            "analytical pipeline, and write showcase.json, report.md, report.html and graph.svg."
        ),
    )
    parser.add_argument(
        "--output-dir", default="showcase-output", type=Path,
        help="directory for the artifacts (default: ./showcase-output)",
    )
    parser.add_argument(
        "--database-url", default=None,
        help="SQLAlchemy async PostgreSQL URL (default: the DATABASE_URL environment variable; "
             "prefer the environment variable so credentials do not appear in the process list)",
    )
    parser.add_argument(
        "--engine-metadata", default=_DEFAULT_ENGINE_METADATA,
        help=f"engine identity metadata file (default: {_DEFAULT_ENGINE_METADATA}, as written in the "
             f"container image)",
    )
    return parser


def _is_asyncpg_url(database_url: str) -> bool:
    # Parse errors quote the URL (including any password), so they are never
    # surfaced; only a yes/no answer leaves this function (SEC-11).
    try:
        url = make_url(database_url)
        _ = url.port
    except Exception:  # noqa: BLE001 - any parse failure is simply "invalid"
        return False
    return url.drivername == "postgresql+asyncpg" and bool(url.database)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        print("error: set DATABASE_URL (or pass --database-url) to an empty, migrated "
              "AttackGraph PostgreSQL database", file=sys.stderr)
        return 2
    if not _is_asyncpg_url(database_url):
        print("error: DATABASE_URL is not a valid postgresql+asyncpg URL (value not shown)", file=sys.stderr)
        return 2
    try:
        report = asyncio.run(run_showcase(database_url, EngineIdentityService(args.engine_metadata)))
        written = write_artifacts(report, args.output_dir)
    except (ShowcaseDatabaseNotReady, ShowcaseConsistencyError, ArtifactWriteError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, DBAPIError):
        # Connection errors can echo connection details; report generically (SEC-11).
        print("error: could not connect to the database; is PostgreSQL running and DATABASE_URL correct?",
              file=sys.stderr)
        return 1

    featured = report.remediation.featured_relationship_id
    names = {e.id: e.name for e in report.environment.entities}
    relationship = next(r for r in report.environment.relationships if r.id == featured)
    print("AttackGraph showcase (synthetic environment)")
    print(f"  plausible paths:        {report.baseline.path_count} "
          f"(termination {report.baseline.termination_reason})")
    print(f"  environment risk:       {report.baseline.environment_risk:.8f}")
    print(f"  top remediation:        remove {names[relationship.source_entity_id]} "
          f"-{relationship.relationship_type}-> {names[relationship.target_entity_id]}")
    print(f"  after remediation:      {report.remediation.after.path_count} paths, environment risk "
          f"{report.remediation.after.environment_risk:.8f}")
    print(f"  policy fingerprint:     {report.analysis.provenance.policy_fingerprint}")
    print(f"  engine identity:        {report.engine_identity.status}")
    for path in written:
        print(f"  wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
