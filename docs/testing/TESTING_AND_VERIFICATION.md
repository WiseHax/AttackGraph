# TESTING_AND_VERIFICATION.md

**Tier 4.** Authoritative on how change is verified.

**Premise:** the existing suite proves that the engines compute what they were told to
compute. It does not prove that the security semantics are right, because the fixtures and
the engines were authored by the same reasoning. Tests here are therefore treated as a
**semantic record**, not a build gate. Editing a test is editing the record.

---

## 1. Test taxonomy

Every test belongs to exactly one category. State the category in the test's docstring or
name so future agents know what they are allowed to reason about.

| Category | Asserts | May an agent change it? |
|---|---|---|
| **Unit** | a function's local contract | Yes, with justification |
| **Invariant** | an `ARCH-*` / `ANA-*` / `SEC-*` rule holds | **No** — maintainer only |
| **Semantic / golden** | a known environment produces known analytical output | **No** — maintainer only |
| **Determinism** | repeated runs are byte-identical | **No** |
| **Regression** | a fixed defect stays fixed | **No** without linking the defect |
| **Negative / adversarial** | a *plausible but wrong* conclusion is rejected | **No** |
| **Property** | a relationship holds across generated inputs | Yes, carefully |

---

## 2. Invariant tests

**TEST-1 — Architectural and analytical invariants are tested, not merely documented.**

Invariants that warrant direct test coverage:

- Canonical state is unchanged after any analytical run, including counterfactual runs
  (ARCH-4, ARCH-17).
- The projection is reconstructible from canonical state and equivalent across rebuilds
  (ARCH-5).
- Evidence records are never mutated by analysis (ARCH-6, ANA-10).
- Parallel edges are not collapsed by projection or by counterfactual cloning (ARCH-15).
- Every risk result carries a breakdown (ANA-14) and a policy fingerprint (ANA-5).
- Saturated enumeration is reported, and saturation propagates to derived metrics (ANA-7).
- Both traversal bounds are enforced and are independently effective (ARCH-12).
- No analytical code path reads the wall clock (ANA-3).
- Cross-fingerprint comparison is refused or flagged, never performed silently (ARCH-20).

**TEST-2 — An invariant test failing is never "flaky."** Treat it as a genuine violation
until proven otherwise in writing.

---

## 3. Golden environments

**TEST-3 — Golden environments are sealed fixtures.** They encode "this environment has
these attack paths, and these risk values, under this policy." They are the closest thing the
project has to a specification of intended security semantics.

**TEST-4 — A golden expected value may never be updated to match observed output.**

That operation — "the code produced 63, so the expected value is now 63" — converts a
specification into a transcript and destroys the test's entire purpose. It is prohibited
without a maintainer decision recorded in the change.

**TEST-5 — Legitimate golden updates exist and are rare.** They require: a written argument
that the *previous* expectation was wrong, the analytical reason, the rule or version change
that justifies it, and maintainer approval. A version bump (ANA-4) normally means adding new
expectations for the new version rather than editing the old ones.

**TEST-6 — Golden fixtures must be synthetic** (SEC-6) and should be small enough that a
human can verify the expected paths by hand. A golden fixture nobody can reason about is not
a specification.

**TEST-7 — Negative fixtures are as valuable as positive ones.** [CURRENT, under-built]
Environments containing a *plausible-looking but invalid* path — one a security engineer would
reject — with the expectation that the engine also rejects it. These are the only tests that
can catch over-permissive semantics. New analytical work should add them.

---

## 4. Determinism verification

**TEST-8 — Determinism is tested explicitly, not assumed.**

- Run the same analysis twice in one process and across processes; results must be identical
  including ordering and breakdown contents.
- Vary process hash seed and insertion order of inputs where possible; results must not move.
- Fix the injected evaluation time and confirm freshness-dependent results are stable.
- Confirm that the policy fingerprint is stable for unchanged policy and changes when any
  fingerprinted value changes. Both directions matter: a fingerprint that never changes is as
  broken as one that changes spuriously.

---

## 5. Prohibited test modifications

**TEST-9 — An AI agent may not do any of the following to reach green:**

- delete a test
- rename a test so it is no longer collected
- mark a test skipped, ignored, or expected-to-fail
- widen an assertion tolerance
- replace an exact assertion with a looser one
- edit a golden expected value
- change a fixture so the code's current behaviour becomes correct
- wrap a failing call in exception handling to bypass it
- remove a determinism, fingerprint, saturation, or invariant assertion
- reduce enumeration bounds so a failing case is no longer reached
- add a conditional to a test so it passes in the current configuration

**TEST-10 — Each of these is a STOP (S7), not a judgement call.** If you believe a test is
genuinely wrong, say so in the report with your reasoning and stop. Being right about a wrong
test does not authorise you to change it silently.

---

## 6. Test authoring standards

**TEST-11 — Tests assert semantics, not implementation.** Assert that the correct path set
is found, not that a helper was called three times. Implementation-coupled tests make
refactoring impossible and provide no semantic protection.

**TEST-12 — One behaviour per test, with a name stating the behaviour.**
`test_saturated_path_set_marks_environment_risk_saturated` is a specification.
`test_risk_2` is noise.

**TEST-13 — No hidden coupling between tests.** No shared mutable state, no ordering
dependence, no reliance on a previous test's side effects.

**TEST-14 — No network, no live database dependency in unit and semantic tests, no sleeping
on wall-clock time.** Inject time; never wait for it.

**TEST-15 — New analytical capability requires, at minimum:** a semantic test on a golden
environment, a determinism test, a saturation-behaviour test, a fingerprint-contribution
test, and at least one negative fixture.

**TEST-16 — Coverage percentage is not a goal.** Semantic coverage is. A suite at high line
coverage with no invariant or negative tests is weakly protective. State what your tests
*prove*, not what they touch.

---

## 7. Triage procedure for a failing test

Follow in order. Do not skip to step 4.

1. **Reproduce** and capture exact output. Do not paraphrase a failure.
2. **Classify** the test (§1). Invariant, golden, determinism and negative failures are
   presumed to indicate a real defect in the change.
3. **Determine which side encodes intended semantics**, using the source-of-truth hierarchy:
   Tier 1–3 documents decide, then the test, then the code. Write the conclusion down.
4. **Act:**
   - *Code is wrong* → fix the code.
   - *Test is wrong* → **STOP (S7)** and report. Do not edit it.
   - *Documents are silent* → **STOP (S8)**. Ambiguity is not yours to resolve.
   - *Fixing requires a semantic change* → that is a new version (ANA-4), not a fix. STOP.
5. **Re-run the full suite**, not only the failing test. A targeted green is not a green.

---

## 8. Verification checklist before reporting

- [ ] Full suite run, from a clean state, with the exact command and full result recorded.
- [ ] No test was deleted, skipped, renamed out of collection, weakened, or edited.
- [ ] New behaviour has semantic, determinism, saturation and fingerprint coverage.
- [ ] At least one negative fixture where the change touches path or risk semantics.
- [ ] Determinism verified by repeated runs, not assumed.
- [ ] Canonical immutability verified for anything touching analysis.
- [ ] Any pre-existing failure is reported as pre-existing, with evidence that it predates
      the change — never silently inherited and never silently fixed.
- [ ] Test counts before and after are stated explicitly in the report.

---

## 9. CURRENT vs FUTURE

**[CURRENT]** — §§1–8.

**[FUTURE]** — not to be introduced without an authorised phase:

- performance benchmarking gates and regression thresholds
- large-scale generated environments for scale testing
- mutation testing
- sensitivity/stability testing that perturbs weights and bounds to measure ranking robustness
  (analytically valuable; a distinct capability, not a test-suite change)
- fuzzing of the import path (valuable; requires authorisation as it touches ingestion)

---

## 10. Rule index

| ID | Rule |
|---|---|
| TEST-1/2 | Invariants tested; invariant failures are real |
| TEST-3–7 | Golden fixtures sealed; no fitting to output; negative fixtures required |
| TEST-8 | Determinism verified explicitly, both fingerprint directions |
| TEST-9/10 | Prohibited test modifications; each is a STOP |
| TEST-11–16 | Authoring standards; semantic over structural coverage |
