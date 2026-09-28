# Contributing to AttackGraph

Thank you for your interest in AttackGraph. This project's value rests on the
trustworthiness of its numbers, so contributions are held to an explicit engineering
discipline. Please read this guide before opening a pull request.

> **License:** AttackGraph is licensed under the [MIT License](LICENSE). Please open an issue to
> discuss any substantial contribution before investing significant effort.

## Scope: what AttackGraph is and is not

AttackGraph is a **defensive** analytics platform for **authorized** environments. The
following are permanently out of scope and will not be accepted
([AGENTS.md §2](AGENTS.md), SEC-1, ANA-18):

- exploitation, probing, scanning, or any capability that acts on a real environment
- autonomous agents that change monitored environments
- machine-learned, opaque, or AI-generated risk scores or findings
- offensive tooling of any kind, including "for testing"

## Before you start

1. Read the governance documents, in this order:
   [Architecture rules](docs/architecture/ARCHITECTURE_RULES.md),
   [Analytical integrity rules](docs/analytics/ANALYTICAL_INTEGRITY_RULES.md),
   [Security engineering rules](docs/security/SECURITY_ENGINEERING_RULES.md),
   [Testing and verification](docs/testing/TESTING_AND_VERIFICATION.md),
   [Code standards](docs/engineering/CODE_STANDARDS.md) and the
   [Definition of done](docs/engineering/DEFINITION_OF_DONE.md).
   Where they conflict, the hierarchy in [AGENTS.md §4](AGENTS.md) decides.
2. For anything beyond a small fix, open an issue (use the *Engineering proposal* template for
   architectural or analytical changes) and agree on the approach first.
3. Items marked `[FUTURE]` in the documents are direction, not open tasks: they need a
   separately agreed phase before implementation.

## Development setup

Follow the [Quick start in the README](README.md) to configure `.env`, start PostgreSQL with
Docker Compose, install `backend/requirements.txt` and apply migrations. Never commit `.env`
or any real credential.

## Workflow

Every change follows:

```
UNDERSTAND → INSPECT → PLAN → IMPLEMENT → TEST → AUDIT → REPORT
```

In practice:

- **One concern per change.** Keep diffs minimal and focused; no drive-by refactors,
  renames or reformatting of files you are not otherwise changing (ARCH-27, CODE-30/31).
- **Focused commits** with conventional messages that state what changed and why, e.g.
  `fix: harden counterfactual fail-closed behavior`. Reference rule IDs where relevant and
  call out any version bump, fingerprint change or disclosure.
- **No new dependencies** without prior maintainer agreement (CODE-14 / SEC-14). Pin what you
  are given.
- **No database migrations** without explicit agreement (ARCH-23).

## Analytical and determinism expectations

- Analytical computations must be deterministic: no wall-clock reads (evaluation time is an
  injected, timezone-aware input), no unseeded randomness, no dependence on hash seeds or
  iteration order, and a total order with stable tie-breaks for every list and ranking.
- Never write analytical output back into canonical storage, and never mutate evidence.
- Every risk value ships with its structured breakdown and policy fingerprint; saturation is
  reported, never hidden.
- A change to what a versioned formula means (`risk-v1`, `env-risk-v1`, `decay-policy-v1`,
  …) is a **new version**, never an in-place edit. `env-risk-v1` is frozen.
- Analysis code uses `GraphStore` / `TraversalEngine`, never NetworkX directly.

## Testing expectations

Run the suite from `backend/` (see [README](README.md)).
The integration tests drop and recreate the schema of the database in `TEST_DATABASE_URL`;
use only a dedicated test database.

- New behaviour needs tests that prove its semantics; new analytical capability additionally
  needs determinism, saturation and fingerprint coverage and at least one negative fixture
  (TEST-15).
- **Never make a test pass by weakening it.** Do not delete, skip, loosen, or re-baseline
  tests, and do not edit golden values to match output (TEST-9). If you believe a test is
  wrong, say so in the PR with your reasoning and leave it unchanged.
- Report the exact test command and counts before and after your change.

## Documentation expectations

Update documentation in the same change as the behaviour it describes (CODE-33). Do not
soften or remove documented limitations (ANA-17), and do not reword `[FUTURE]` items as if
they were current.

## Security-sensitive changes

Changes touching untrusted input, secrets handling, engine identity, the Docker image, or
dependencies need a short security note in the PR: what could go wrong and how the change
fails closed. Never include real credentials or data from a real environment in code, tests,
fixtures or examples; test data must be recognisably synthetic (SEC-6). To report a
vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Pull requests

Use the pull request template. A PR is ready for review when it:

- states the problem, the scope and what is explicitly out of scope
- lists the invariants engaged and any analytical impact (semantics, fingerprint, saturation)
- includes tests and the full test result
- updates documentation where behaviour changed
- raises (rather than silently resolves) any ambiguity in the governance documents

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
