# AttackGraph showcase

The files in this directory are the committed output of one showcase run:

| File | Contents |
|---|---|
| [`report.md`](report.md) | Human-readable security analysis report (renders on GitHub) |
| [`report.html`](report.html) | The same report as a standalone page (inline CSS and SVG, no scripts or external resources) |
| [`graph.svg`](graph.svg) | The environment graph, with plausible paths and the top-ranked remediation candidate |
| [`showcase.json`](showcase.json) | The complete, machine-readable result (schema `attackgraph-showcase-v1`) |

They are generated, never edited by hand. A test regenerates them against PostgreSQL and fails if
they differ in any byte, so they always show what the current engine actually produces.

## Running it

Prerequisites: the PostgreSQL database from the [Quick start](../../README.md#quick-start),
migrated to the Alembic head and **empty**, and `DATABASE_URL` pointing at it.

```bash
cd backend
set -a && . ../.env && set +a
python -m app.showcase                         # writes to ./showcase-output/
python -m app.showcase --output-dir ../docs/showcase   # regenerate these files
```

What happens:

1. The database is checked: PostgreSQL, at the Alembic head, with no canonical data. With a
   universal scope every entity in the database would enter the analysis, so a non-empty
   database is refused rather than mixed into the report.
2. The synthetic environment in `backend/app/showcase/fixture.py` is written through the
   canonical repositories, inside a transaction that is **always rolled back**.
3. The scope is resolved by exact `(scope_id, definition_version)`; an `AnalysisContext` combines
   `AnalysisPolicyV2`, a fixed UTC evaluation time and that scope.
4. `GraphBuilder` projects the graph; `TraversalEngine` enumerates paths under the policy's
   bounds; risk-v1 scores each path and env-risk-v1 aggregates them.
5. `CounterfactualEngine` evaluates removing every relationship on a path, under the same
   policy. The showcase checks that its own baseline and the engine's baseline agree exactly and
   fails otherwise.
6. The same analysis runs with a lower `max_paths` to show saturation semantics.
7. The result is written as JSON, Markdown, HTML and SVG. Only these four files are written.

Engine identity is reported as it is: outside a verified container build it is
`ENGINE_UNVERIFIABLE`, so the persistence preconditions are not met. Persistence of analytical
results is not implemented.

## What it demonstrates

- The real pipeline from canonical records to a ranked, counterfactual remediation, with no
  analytics re-implemented for the demonstration.
- Evidence lineage (including decay of stale evidence and an inferred relationship without
  evidence), parallel-relationship path identity, risk breakdowns, saturation and termination
  semantics, policy fingerprints, comparability refusal and persistence-authority gates.
- Determinism: the same fixture and evaluation time produce byte-identical output on every run
  and platform; only the engine-identity section reflects where the run happens (a development
  checkout versus a verified container build).

## What it does not demonstrate

- Anything about a real organisation or system. Example Corp is fictional; hostnames use the
  reserved `.test` TLD and addresses the RFC 5737 documentation ranges.
- That any path is exploitable, or that the environment would be secure after a change. Paths are
  plausible under the model and the policy's bounds.
- Calibrated risk. risk-v1 weights and decay parameters are uncalibrated modelling choices, and
  env-risk-v1 counts overlapping paths more than once, so with many paths it approaches 1. Use
  the differences under one fixed policy, not the absolute levels.
- Data collection. AttackGraph does not scan, probe or act on any environment.
