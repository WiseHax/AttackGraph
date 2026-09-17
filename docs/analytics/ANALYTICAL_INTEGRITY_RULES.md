# ANALYTICAL_INTEGRITY_RULES.md

**Tier 3.** Subordinate to `ARCHITECTURE_RULES.md` (Tier 1) and
`SECURITY_ENGINEERING_RULES.md` (Tier 2). Authoritative on the meaning and presentation of
analytical results.

**Premise:** AttackGraph's differentiation is not that it computes numbers. It is that its
numbers can be defended in front of a sceptical security engineer. Every rule here exists to
keep a number defensible. A number that cannot be explained, reproduced, or bounded is worse
than no number, because it will be believed.

---

## 1. Truth tiers [CURRENT]

**ANA-1 — Three tiers exist and must remain structurally distinguishable.**

| Tier | Meaning | Origin |
|---|---|---|
| **OBSERVED** | A source directly asserted this | evidence-backed relationship |
| **INFERRED** | Derived from observations by an explicit rule | rule + referenced observations |
| **ANALYTICAL** | A conclusion produced by the analysis layer | computation over the graph |

**ANA-2 — Inference must never be presented as observation, and analysis must never be
presented as either.** This applies to data structures, serialisation, logs, and any
human-facing output. An analytical conclusion must never be storable as an observed
relationship (ARCH-4 makes this structural; do not weaken it for convenience).

An INFERRED result must be able to name the observations it was derived from. If a rule
produces an inference that cannot cite its inputs, the rule is incomplete.

---

## 2. Determinism [CURRENT]

**ANA-3 — Every analytical computation is deterministic.** Given identical canonical state
and identical policy, a computation must produce byte-identical results, including ordering.

Forbidden inside analytical code paths:

- unseeded randomness of any kind
- wall-clock reads that are not an explicitly injected evaluation time
- dependence on iteration order of unordered collections
- dependence on hash seeds, memory addresses, or object identity
- concurrency whose result depends on scheduling
- network calls, external services, or any I/O whose result can vary
- locale-, timezone-, or environment-dependent formatting or comparison

**Evaluation time is an input, not an ambient fact.** Freshness and decay depend on a
reference time; that time must be passed in explicitly so that a computation can be
reproduced exactly at a later date. Reading the clock inside an analysis function makes the
result unreproducible and is a violation.

**Ordering is part of the result.** Path lists, rankings and factor breakdowns must have a
fully specified total order, including deterministic tie-breaking on a stable key. "The order
doesn't matter" is false here: it matters for reproducibility, diffing, and hashing.

---

## 3. Analytical policy versioning [CURRENT]

**ANA-4 — The semantics of a versioned analytical formula never change in place.**

If a change alters *what a number means* — weights, factor structure, aggregation, bounds
with semantic meaning, decay behaviour, confidence handling — it requires a **new version
identifier**. The existing version continues to behave exactly as before.

Permitted without a version bump: performance work, refactoring, and bug fixes that restore
the documented intended behaviour. A "bug fix" that changes documented intended behaviour is
not a bug fix; it is a new version.

**ANA-4a — Version coexistence is bounded.** [CURRENT] Unbounded proliferation of live
formula versions is a maintenance and support failure. Keep the number of simultaneously live
versions small and deliberate; retiring a version is a maintainer decision, never an agent's.

**ANA-4b — `env-risk-v1` is frozen.** See ARCH-25. STOP S2.

---

## 4. Policy fingerprints and comparability [CURRENT]

**ANA-5 — Every analytical result carries the policy fingerprint that produced it.**

The fingerprint identifies the complete analytical configuration: formula versions in use,
aggregation version, both traversal bounds, enumeration limits, cost and weight tables, and
decay parameters. If a value can change a result, it belongs in the fingerprint.

**ANA-6 — Results with differing fingerprints are not comparable.** (ARCH-20.)

A consequence agents routinely miss: a configuration change produces a risk delta that is
**an analysis change, not a posture change**. Presenting it as a posture change is a
correctness failure, not a cosmetic one. Any comparison feature must refuse or loudly flag
cross-fingerprint comparison.

Adding a new input to the fingerprint is a deliberate act with consequences — it invalidates
comparability with prior results. Do it when correctness requires it, and say so in the
report.

---

## 5. Saturation semantics [CURRENT]

**ANA-7 — Saturation is part of the result, never a hidden condition.**

When enumeration reaches a configured limit, the result is **a lower bound, not a
measurement**. It must be labelled as such and must state the bound that was reached.

Rules:

- Saturation state is never dropped, defaulted to false, or silently swallowed.
- Saturation **propagates**: any metric derived from a saturated path set inherits saturated
  status. Overlap, choke-point and participation metrics, environment aggregation,
  counterfactual deltas and posture outputs are all downstream of path enumeration.
- A saturated result must never be presented with the same confidence language as an
  unsaturated one.
- Raising a limit to "avoid saturation" changes the fingerprint and the comparability class.

> **[OPEN] A-3.** Whether propagation is fully implemented today is not established by the
> materials. Treat propagation as **required**; if your change depends on current behaviour,
> STOP S8 rather than assuming.

**Why this matters more than it looks:** because enumeration is capped, scale pressure in
this system does not appear as slowness. It appears as *silent quality degradation* —
truncated path sets producing understated risk and biased structural metrics, with no visible
symptom. Saturation reporting is the only thing that makes that failure visible.

---

## 6. Bounded traversal semantics [CURRENT]

**ANA-8 — Respect the meaning of each bound.** (ARCH-12.)

- `max_hops` is computational safety. Tuning it is a tractability decision.
- `traversal_budget` is a claim about plausible attacker effort. Tuning it is an **analytical
  policy change** and requires version treatment per ANA-4.

Never tune a semantic bound to make a test pass, to surface a path a user expected, or to
reduce runtime. The first is falsification (see §11), the second is fitting the model to an
anecdote, the third has a correct alternative in `max_hops`.

---

## 7. Evidence, confidence and decay [CURRENT]

**ANA-9 — Confidence discounts; it never inflates.** Low confidence must reduce or
qualify a conclusion. No code path may allow uncertainty to increase a risk value.

**ANA-10 — Freshness downgrade is analytical.** Decay is computed at analysis time from
canonical evidence plus an injected evaluation time. It never mutates, overwrites, or deletes
canonical evidence (ARCH-6). Stale evidence is **discounted and flagged**, never removed.

**ANA-11 — Source-aware confidence handling must be preserved.** Confidences originating from
a common source are correlated; treating them as independent systematically distorts results.
Do not replace source-aware handling with naive per-edge combination as a "simplification."

**ANA-12 — Uncalibrated constants must be disclosed as modelling choices.** [OPEN] A-5.
Decay parameters, traversal costs and risk weights are structurally defensible; their
magnitudes are not established as empirically calibrated. Documentation and any explanation
output must not present them as measurements. A plausible constant wearing the costume of a
measurement is the fastest route to losing user trust.

**ANA-13 — Contested evidence is not the same as low-confidence evidence.** [OPEN]
Conflicting assertions from different sources are epistemically distinct from a single weak
assertion. If the current model collapses them, do not deepen that collapse; do not "fix" it
either without authorisation. Record it.

---

## 8. Explainability [CURRENT]

**ANA-14 — No bare scores. Ever.** Every risk value ships with its factor breakdown: which
factors contributed, how much, under which assumptions, and how confidence affected the
result. A score emitted without a breakdown is an incomplete result, not a compact one.

**ANA-15 — Breakdowns are structured data, not log lines or prose.** They are consumed by
comparison, attribution and explanation features. Formatting a breakdown into a string and
discarding the structure destroys downstream capability.

**ANA-16 — Every meaningful conclusion is traceable to evidence.** A relationship-derived
conclusion must be able to name the evidence supporting it.

---

## 9. Known limitation disclosure [FROZEN]

**ANA-17 — Known analytical limitations are disclosed, not hidden.**

Specifically and currently:

- **Path overlap / double counting (A-2).** Environment aggregation may over-count correlated
  paths. `env-risk-v1` is frozen; the required response is disclosure in documentation and in
  any explanation surface, **not** silent correction.
- **Levels versus deltas.** Counterfactual *deltas* computed under a single fixed policy are
  more defensible than absolute *levels*, because most modelling error cancels in a
  difference. Where the system can emphasise a delta over a level, it should. Where it
  presents a level, it should not overclaim.
- **Bound dependence.** Risk is a function of the analysis configuration as well as the
  environment (ANA-5, ANA-7).

Removing or softening a disclosure is a governance violation.

---

## 10. Permanent analytical prohibitions

**ANA-18 — No learned, opaque, or AI-generated scoring.** No GNN risk scoring, no ML-fitted
weights presented as risk, no LLM-produced risk values. This is permanent. It is not deferred.
Determinism is the property every other capability in this system is built on; trading it for
accuracy claims that cannot be audited destroys the product.

**ANA-19 — AI must never be a source of findings, relationships, evidence, or scores.**
Any future explanation layer is read-only over deterministic results, must cite the graph and
evidence objects it refers to, and must never write to canonical or derived stores. [FUTURE]

**ANA-20 — No exploitation, probing, or validation-by-execution.** Attack paths are
*analytical* conclusions. The system never attempts to confirm one by acting on a real
system. Permanent. (SEC-1.)

**ANA-21 — No automatic probabilistic entity merging.** Deterministic matching only.
Probabilistic matching, if ever introduced, is suggestion-only and human-confirmed, because a
silent bad merge is unrecoverable data corruption. [FUTURE, constrained]

---

## 11. Adding a new analytical capability

A new metric or analysis must declare, before implementation:

1. **Question** it answers, in one sentence a security engineer would recognise.
2. **Inputs**, including which canonical data and which policy values.
3. **Method**, and the assumption it rests on.
4. **Output shape**, including breakdown structure.
5. **Fingerprint contribution** — which new policy values enter the fingerprint.
6. **Saturation behaviour** — how it inherits and reports saturation.
7. **Bound sensitivity** — how the result changes with `max_hops`, `traversal_budget` and
   enumeration limits.
8. **Failure modes** — when it produces a misleading answer.
9. **Disclosure** — which limitations must be stated alongside it.

A metric that cannot answer all nine is not ready. "It looked interesting" is not a
justification; the fastest way to make this platform meaningless is to add numbers whose
stability nobody has checked.

---

## 12. The falsification rule

**ANA-22 — Never make a test pass by weakening the intended semantics of the system.**

Analytical instances of this violation, all prohibited:

- widening a semantic bound so an expected path appears
- lowering a confidence threshold so a result clears it
- editing a golden expected value to match observed output
- relaxing a determinism or ordering assertion
- suppressing saturation so a comparison proceeds
- removing a fingerprint check so two results become comparable
- rounding, clamping, or truncating to hide a discrepancy

If the code and the test disagree, one of them encodes the wrong semantics. Determining which
is an analysis task with a written conclusion — not a guess resolved by editing whichever is
easier. See `TESTING_AND_VERIFICATION.md` §7.

---

## 13. Rule index

| ID | Rule |
|---|---|
| ANA-1/2 | Truth tiers; never present inference as fact |
| ANA-3 | Determinism, injected time, total ordering |
| ANA-4 | Version-additive semantics; bounded coexistence; v1 frozen |
| ANA-5/6 | Fingerprints; comparability |
| ANA-7 | Saturation reported and propagated |
| ANA-8 | Bound semantics respected |
| ANA-9/10/11 | Confidence discounts; decay analytical; source-aware handling |
| ANA-12/13 | Disclose uncalibrated constants; contested ≠ low confidence |
| ANA-14/15/16 | Breakdowns mandatory, structured, evidence-traceable |
| ANA-17 | Known limitations disclosed |
| ANA-18–21 | Permanent prohibitions |
| ANA-22 | Never weaken semantics to pass a test |
