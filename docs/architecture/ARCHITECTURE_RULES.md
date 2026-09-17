# ARCHITECTURE_RULES.md

**Tier 1 — highest-authority engineering document.** Overridden only by an explicit human
maintainer instruction, and never on a permanent prohibition.

**Scope:** structural invariants of AttackGraph. What may depend on what, what is true versus
what is computed, and what must never change without a recorded architecture decision.

**Phase context:** Phases 1–6 sealed; Phase 7A in progress.

---

## 1. Layer model and dependency direction [CURRENT]

**ARCH-1 — Dependency direction is one-way and non-negotiable.**

```
          ┌──────────────────────────────────────────┐
          │  Interface / delivery layer              │   (may import everything below)
          └──────────────────┬───────────────────────┘
                             │
          ┌──────────────────▼───────────────────────┐
          │  Analysis layer                          │
          │   traversal · risk · counterfactual ·    │
          │   remediation · posture · overlap        │
          └──────────────────┬───────────────────────┘
                             │
          ┌──────────────────▼───────────────────────┐
          │  Projection layer                        │
          │   GraphStore · TraversalEngine           │
          └──────────────────┬───────────────────────┘
                             │
          ┌──────────────────▼───────────────────────┐
          │  Canonical layer                         │
          │   PostgreSQL · entities · relationships  │
          │   evidence · findings                    │
          └──────────────────┬───────────────────────┘
                             │
          ┌──────────────────▼───────────────────────┐
          │  Domain layer                            │
          │   types · enums · value objects · policy │
          └──────────────────────────────────────────┘
```

Imports point **downward only**. No upward import, no lateral import that creates a cycle.

**ARCH-2 — The domain layer imports nothing from higher layers.** It must be loadable with
no database, no graph library, and no I/O.

**ARCH-3 — The canonical layer must not import from the analysis layer.** If canonical code
needs an analytical concept, the concept is in the wrong layer.

> Enforcement note for agents: if satisfying a task requires an upward import, you have a
> layering error, not an import problem. STOP (S6) and report.

---

## 2. Canonical truth versus derived analysis [CURRENT]

**ARCH-4 — PostgreSQL is the single canonical source of truth. Analytical output must never
be written back into canonical storage.**

Canonical (facts, persisted, authoritative):
- assets / entities and their attributes
- relationships and their provenance
- evidence records
- findings

Derived (computed, disposable, never authoritative):
- the graph projection
- attack paths
- path identity values
- risk scores and breakdowns
- environment risk aggregation
- overlap, choke-point and participation metrics
- posture output
- counterfactual results and remediation rankings

**ARCH-5 — The graph projection is rebuildable and disposable.** Any projection must be
reconstructible from canonical state alone. No fact may exist only in the projection. If a
change would make the projection the only place some information lives, the change is
invalid.

**ARCH-6 — Canonical evidence is immutable.** Evidence records are not edited in place.
Corrections and supersessions are expressed by adding records, never by mutating or deleting
existing ones. Analytical adjustments to evidence — including freshness downgrade — are
computed at analysis time and **never** written back. (See ANA-8.)

**ARCH-7 — Findings are relational entities, not graph nodes.** Findings attach to entities
and may influence edge weighting or risk factors. They are never traversable objects. Any
proposal to promote findings to nodes is a redesign and out of scope for any normal task.

---

## 3. Projection boundary: GraphStore and TraversalEngine [CURRENT]

**ARCH-8 — `GraphStore` owns representation and persistence-of-projection concerns.**
It answers structural questions: nodes, edges, neighbours, subgraphs, identity.

**ARCH-9 — `TraversalEngine` owns traversal algorithms and bounds.**
It answers path questions. It consumes `GraphStore`; `GraphStore` must not depend on it.

**ARCH-10 — Analysis code must not reach around these interfaces into the underlying graph
library.** NetworkX is an implementation detail of the projection layer. Direct NetworkX
usage above the projection layer defeats the abstraction boundary that exists specifically
to permit a future backend change.

**ARCH-11 — No analytical policy may live inside `GraphStore`.** Costs, budgets, weights,
decay constants and thresholds are policy data (ARCH-13), not storage behaviour.

---

## 4. Bounded traversal [CURRENT]

AttackGraph deliberately maintains **two distinct bounds with different meanings.** They are
not interchangeable and must never be collapsed into one.

**ARCH-12 — Bound semantics are fixed:**

| Bound | Kind | Meaning | May be tuned for |
|---|---|---|---|
| `max_hops` | computational safety bound | hard ceiling preventing unbounded work | tractability |
| `traversal_budget` | semantic plausibility bound | the modelled limit of attacker effort | security realism |

Consequences:

- A change that raises `max_hops` for performance reasons is a **tractability** change.
- A change that alters `traversal_budget` changes **what the system believes is a plausible
  attack** and is therefore an analytical policy change requiring versioning (ANA-4).
- Neither bound may be removed.
- Neither bound may silently default to the other's value.
- Both bounds are inputs to the policy fingerprint (ANA-5).

---

## 5. Analytical policy as versioned data [CURRENT]

**ARCH-13 — Analytical policy is data, not code constants.** Weights, costs, budgets, decay
parameters, thresholds and formula selectors belong to an explicit, versioned policy object.
A magic number embedded in an analysis function is an architecture violation because it
cannot be fingerprinted, versioned, or audited.

Versioned analytical artefacts currently in the system include the risk formula versions and
the environment risk aggregation version (`env-risk-v1`).

---

## 6. Identity rules [CURRENT]

**ARCH-14 — Canonical identity is stable and owned by the canonical layer.** Entity identity
must not be derived from display names or from any field that changes for cosmetic reasons.

**ARCH-15 — Parallel-edge identity must be preserved.** Two relationships between the same
pair of entities are distinct objects when their type, direction, or provenance differ. The
projection must not collapse parallel edges into one. Collapsing them destroys provenance and
corrupts both overlap analysis and counterfactual removal, because a removal would then
silently remove more than one asserted relationship.

**ARCH-16 — Path identity is a stable hash over path semantics.** It exists so that the same
path is recognisably the same path across computations.

> **[OPEN] — A-1.** The exact input set to the path identity hash is not specified in the
> materials available to this document. Path identity is only sound if it hashes **semantic
> structure** (canonical entity keys, relationship type, direction, and — given ARCH-15 —
> whatever distinguishes parallel edges) and **excludes** volatile analytical values such as
> confidence, risk, timestamps, freshness state, and policy values. If it currently includes
> volatile values, path identity will churn without underlying change. Any task depending on
> path identity stability triggers STOP S8 until a maintainer confirms the input set.

---

## 7. Counterfactual analysis [CURRENT]

**ARCH-17 — Counterfactual analysis operates on a clone of the projection. Canonical state is
immutable for the entire duration of an analytical run.** No counterfactual path may write to
PostgreSQL, mutate shared projection state, or leave residue visible to a subsequent analysis.

**ARCH-18 — A counterfactual result is a derived artefact.** It carries its policy
fingerprint and its saturation state exactly as any other analytical output does.

**ARCH-19 — Counterfactual changes are expressed through explicit change descriptors**, not
by ad-hoc graph edits scattered through analysis code. Current scope: relationship removal.
Any other change kind is a new capability requiring authorisation.

---

## 8. Comparability [CURRENT]

**ARCH-20 — Two analytical results are comparable only if their policy fingerprints match.**
Comparison across differing fingerprints must be refused or explicitly flagged as
non-comparable. It must never be performed silently. This applies to any future delta,
trend, or before/after presentation.

---

## 9. Ingestion and semantics ownership [CURRENT]

**ARCH-21 — Graph semantics are owned centrally, never by an ingestion source.** Any importer
or connector produces normalised entities, relationships and evidence. It does not decide
what an edge means, what it is worth, or how it is scored. This rule exists to prevent each
new data source from inventing its own security semantics.

**ARCH-22 — All imported data is untrusted input.** See `SECURITY_ENGINEERING_RULES.md` §4.

---

## 10. Change discipline [CURRENT]

**ARCH-23 — No migrations.** [FROZEN] Database schema changes and migrations are outside the
scope of normal agent work. A task that appears to need one is STOP S1.

**ARCH-24 — Sealed phases are sealed.** Phases 1–6 behaviour is a regression baseline.
Changing observable behaviour of a sealed phase requires a maintainer decision, a version
bump where semantics change, and an explicit note in the report.

**ARCH-25 — `env-risk-v1` is frozen.** [FROZEN] It must not be modified, and `env-risk-v2`
must not be introduced, under any normal task. This freeze is deliberate and is held despite
the known limitation recorded in §12 (A-2). Encountering that limitation is not authorisation
to fix it. STOP S2.

**ARCH-26 — Behaviour-changing work is version-additive, not edit-in-place.** See ANA-4.

**ARCH-27 — One concern per change.** Structural refactors, behaviour changes, and
formatting changes are separate units of work. Mixed changes are unreviewable and are
rejected on that ground alone.

---

## 11. FUTURE direction (documented, not authorised) [FUTURE]

Recorded so agents recognise them as direction rather than gaps to fill. **None of these may
be implemented without a separately authorised phase.**

- Derived-artefact persistence with snapshot binding — prerequisite for temporal analysis.
- Snapshot comparison, path appearance/disappearance, posture drift.
- Risk change attribution by staged replay.
- Delta risk recomputation for counterfactual tractability.
- Overlap-corrected environment aggregation as a **new version** alongside v1.
- Security controls as first-class entities.
- Multi-remediation optimisation.
- Alternative graph backends behind `GraphStore` / `TraversalEngine`.
- A grounded, read-only explanation layer.

Implementing any of these because it appears here is a governance violation (AGENTS.md §9).

---

## 12. Known ambiguities and accepted limitations [OPEN] / [FROZEN]

These are recorded rather than resolved. **Do not resolve them in code.**

**A-1 [OPEN] — Path identity input set.** See ARCH-16.

**A-2 [FROZEN] — Path overlap and environment aggregation.** The system computes path
overlap, Jaccard overlap, and risk-weighted edge participation. Whether `env-risk-v1`
*consumes* overlap correction or merely reports overlap alongside an uncorrected aggregate is
not established by the materials governing this document. If it does not consume it,
environment risk may over-count correlated paths and will tend to rise with graph density.
Because `env-risk-v1` is frozen (ARCH-25), the required response is **disclosure, not
correction** (ANA-10).

**A-3 [OPEN] — Saturation propagation.** Saturation semantics are explicit for traversal. It
is not established whether saturation state propagates into environment risk, overlap,
choke-point, counterfactual and posture outputs derived from a saturated path set. Until
confirmed, treat propagation as required by ANA-7 and STOP S8 if your change depends on
current behaviour.

**A-4 [OPEN] — Interface stability status.** It is not established which interfaces are
formally frozen versus merely stable in practice. Treat `Evidence`, relationship type
definitions, path identity, risk input/result structures, `GraphStore`, `TraversalEngine`,
counterfactual change descriptors and policy/version identifiers as **contractual** until
told otherwise.

**A-5 [OPEN] — Calibration status of constants.** Traversal costs, decay parameters and risk
weights are structurally sound but their magnitudes are not established as empirically
calibrated. Treat them as uncalibrated modelling choices requiring disclosure (ANA-12).

**A-6 [OPEN] — Phase 7A scope.** The precise boundary of Phase 7A is not defined here. Work
outside an explicitly stated task boundary requires confirmation.

**A-7 [OPEN] — Delivery surface.** The materials do not establish that an HTTP API,
frontend, or authentication layer exists. Do not assume one. Do not add one.

---

## 13. Invariant index

| ID | Invariant |
|---|---|
| ARCH-1 | Downward-only dependency direction |
| ARCH-2 | Domain layer is I/O-free |
| ARCH-3 | Canonical layer does not import analysis |
| ARCH-4 | No analytical writeback to canonical |
| ARCH-5 | Projection is rebuildable and disposable |
| ARCH-6 | Canonical evidence is immutable |
| ARCH-7 | Findings are relational, not nodes |
| ARCH-8/9 | GraphStore and TraversalEngine responsibilities |
| ARCH-10 | No graph-library access above the projection layer |
| ARCH-11 | No policy inside GraphStore |
| ARCH-12 | Two distinct traversal bounds |
| ARCH-13 | Policy is versioned data |
| ARCH-14 | Stable canonical identity |
| ARCH-15 | Parallel-edge identity preserved |
| ARCH-16 | Path identity hashes semantics |
| ARCH-17 | Counterfactual clones; canonical immutable |
| ARCH-18 | Counterfactual results carry fingerprint and saturation |
| ARCH-19 | Explicit change descriptors |
| ARCH-20 | Comparability requires matching fingerprints |
| ARCH-21 | Central ownership of graph semantics |
| ARCH-22 | Imported data is untrusted |
| ARCH-23 | No migrations |
| ARCH-24 | Sealed phases are regression baselines |
| ARCH-25 | env-risk-v1 frozen; no env-risk-v2 |
| ARCH-26 | Version-additive change |
| ARCH-27 | One concern per change |
