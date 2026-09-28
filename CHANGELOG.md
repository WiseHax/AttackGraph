# Changelog

All notable changes to AttackGraph are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). AttackGraph has not published a
release yet, so all changes are listed under **Unreleased**, newest first, with the commit
that introduced them.

## [Unreleased]

### Security
- Engine identity verification fails closed: an unknown or non-SHA `source_version`, an
  unknown dirty state (missing, empty or ambiguous `APP_GIT_DIRTY`) and malformed or
  incomplete engine metadata are `ENGINE_UNVERIFIABLE` and cannot authorize persistence
  (SEC-29, SEC-30). (`84c000b`)
- Source digest v2 hashes the files actually delivered into the image instead of emulating
  Docker ignore rules; `.dockerignore` uses recursive patterns so nested caches and
  secret-pattern files are not delivered (SEC-28). (`c6519ee`)

### Added
- `AnalysisContext` and `AnalysisProvenance`: explicit, timezone-aware evaluation time
  normalised to UTC and recorded with policy version, fingerprint and scope identity; naive
  datetimes are rejected. (`1857eba`)
- Exact-version scope resolution from a persisted `ScopeDefinition` to an `AnalyticalScope`
  carrying canonical scope identity; never resolves "latest" (ARCH-28). (`b5cfb73`)
- `AnalysisPolicyV2`: a policy containing only tunable parameters, with formula versions
  denoting their sealed constant sets; legacy v1 policies cannot authorize persistence and are
  not comparable with v2 (ANA-5a). (`e4ff2c7`)
- J-1 scope foundation: `Scope` and immutable, versioned `ScopeDefinition` (v1 `UNIVERSAL` /
  `ALL`) protected by database triggers. (`a9c7156`)
- Reproducible engine identity: source, dependency and substrate digests; hash-pinned
  dependency lockfile; unprivileged runtime container. (`56e55d7`)
- Engineering governance documents (architecture, analytical integrity, security, testing,
  code standards, definition of done, AI playbook); analysis policy fingerprints and
  comparability checks; explicit traversal saturation semantics. (`6d96dca`)
- Counterfactual remediation ranking, `env-risk-v1` environment aggregation, evidence decay,
  source-aware confidence (`risk-v2`, not persistable), path overlap analysis. (`79588d0`)
- Initial public repository: canonical relational model, PostgreSQL migrations, NetworkX
  graph projection, bounded deterministic traversal, `risk-v1`. (`b2e5899`)

### Fixed
- `CounterfactualEngine` fails closed on missing relationship endpoints or a failed
  relationship removal instead of emitting placeholder identities. (`8ae5fa9`)
- Counterfactual path-ID lists are emitted in a specified order, making serialized output
  byte-identical across processes. (`c700a29`)
