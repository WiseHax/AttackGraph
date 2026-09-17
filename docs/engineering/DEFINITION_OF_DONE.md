# DEFINITION_OF_DONE.md

**Tier 6.** A composed gate. It adds no new rules; it states the conditions under which a
change is finished. Where it appears to conflict with a higher tier, the higher tier wins.

**Core principle:** *done* is not *green*. A change is done when it is correct, verified,
explainable, and leaves the repository more trustworthy than it found it.

---

## 1. Universal gates

Every change, without exception, passes all of these.

### G0 — Scope
- [ ] The task is restated, including explicit out-of-scope.
- [ ] No STOP condition applies (AGENTS.md §6), or the task correctly ended in a STOP.
- [ ] The diff contains exactly one concern (ARCH-27, CODE-30).
- [ ] No unrelated refactor, rename, or reformat.

### G1 — Architecture conformance
- [ ] Layering and dependency direction respected (ARCH-1/2/3).
- [ ] Canonical vs derived boundary respected; no analytical writeback (ARCH-4).
- [ ] Projection remains rebuildable and disposable (ARCH-5).
- [ ] Evidence not mutated (ARCH-6); findings not promoted to nodes (ARCH-7).
- [ ] `GraphStore` / `TraversalEngine` boundary respected (ARCH-8/9/10/11).
- [ ] Both traversal bounds intact and distinct (ARCH-12).
- [ ] Parallel-edge identity preserved (ARCH-15).
- [ ] Counterfactual clones; canonical immutable during analysis (ARCH-17).
- [ ] No migration (ARCH-23). `env-risk-v1` untouched; no `env-risk-v2` (ARCH-25).

### G2 — Analytical integrity
- [ ] Truth tiers preserved; nothing inferred or analytical presented as observed (ANA-1/2).
- [ ] Determinism preserved: no clock, no unseeded randomness, total ordering, stable
      tie-breaks (ANA-3).
- [ ] Any semantic change is a **new version**, not an in-place edit (ANA-4).
- [ ] Policy fingerprint present on every result; comparability rules respected (ANA-5/6).
- [ ] Saturation reported and propagated (ANA-7).
- [ ] Confidence discounts only; decay remains analytical (ANA-9/10/11).
- [ ] Every score ships a structured breakdown (ANA-14/15).
- [ ] Known limitations disclosed, not removed or softened (ANA-17).
- [ ] No learned/AI scoring, no AI-sourced findings (ANA-18/19).

### G3 — Security
- [ ] No secrets anywhere in the change (SEC-4).
- [ ] Untrusted input validated at the boundary; no unsafe deserialisation (SEC-8).
- [ ] No dynamic execution, no input-driven dispatch (SEC-9/18).
- [ ] No new network activity, telemetry, or external service calls (SEC-3/26).
- [ ] Logs and errors leak nothing sensitive (SEC-10/11).
- [ ] No new dependencies (SEC-14) — or explicit maintainer approval is recorded.
- [ ] Nothing resembling offensive capability (SEC-1/27).

### G4 — Tests
- [ ] Full suite run from clean state; command and full result recorded.
- [ ] Counts before and after stated explicitly.
- [ ] **No test deleted, skipped, renamed out of collection, weakened, or edited** (TEST-9).
- [ ] New behaviour has semantic + determinism coverage; saturation and fingerprint coverage
      where applicable (TEST-15).
- [ ] At least one negative fixture where path or risk semantics were touched (TEST-7).
- [ ] Pre-existing failures identified as pre-existing, with evidence.

### G5 — Determinism verification
- [ ] Repeated runs produce identical results including ordering.
- [ ] Fingerprint stable for unchanged policy; changes when a fingerprinted value changes.
- [ ] No result depends on execution environment or timing.

### G6 — Documentation
- [ ] Docstrings on new or changed analytical functions state question, inputs, assumptions,
      output shape, limitations (CODE-26).
- [ ] Rule IDs referenced where a line exists to satisfy one (CODE-27).
- [ ] Documentation updated in the same change as the behaviour (CODE-33).
- [ ] New `[OPEN]` questions added to `ARCHITECTURE_RULES.md` §12 if the work surfaced any.

### G7 — Report
- [ ] Report produced in the `AI_ENGINEERING_PLAYBOOK.md` §9 format.
- [ ] Ambiguities raised, not resolved.
- [ ] Assumptions stated with their basis.
- [ ] Deferred work and introduced risks stated honestly.

---

## 2. Additional gates by change type

### 2.1 Bug fix
- [ ] Root cause identified in writing — not just a symptom suppressed.
- [ ] A regression test exists that **fails before** and **passes after**. Demonstrate both.
- [ ] The fix restores *documented intended* behaviour. If it changes intended behaviour, it
      is not a bug fix — it is a new version (ANA-4). Stop and reclassify.

### 2.2 New analytical capability
- [ ] All nine declarations from `ANALYTICAL_INTEGRITY_RULES.md` §11 answered in writing.
- [ ] Bound sensitivity stated: how the result moves with `max_hops`, `traversal_budget` and
      enumeration limits.
- [ ] Saturation inheritance implemented and tested.
- [ ] Fingerprint contribution implemented and tested.
- [ ] Breakdown structure defined and returned.
- [ ] Negative fixture added.
- [ ] Disclosure text written for known limitations.

### 2.3 Refactor (no behaviour change)
- [ ] Explicit claim: **no observable behaviour changes**.
- [ ] Demonstrated by unchanged test results with **no test modified**.
- [ ] No semantic version bump, because nothing semantic moved.
- [ ] Layering improved or unchanged, never degraded.
- [ ] Separate from any functional change in the same series of work.

### 2.4 Performance change
- [ ] Analytical results are **byte-identical** before and after, including ordering.
- [ ] No semantic bound was altered to gain speed (ANA-8). `max_hops` is the tractability
      lever; `traversal_budget` is not.
- [ ] No parallelism whose result depends on scheduling (CODE-7).
- [ ] Measurement method stated; improvement quantified, not asserted.

### 2.5 Dependency change
- [ ] Maintainer approval recorded in the task.
- [ ] Justification: purpose, alternatives rejected, maintenance status, transitive footprint,
      licence, determinism implications.
- [ ] Pinned.
- [ ] No optional-import behaviour switching (CODE-16).

### 2.6 Documentation-only change
- [ ] No behaviour claim is made that the code does not support.
- [ ] No `[FUTURE]` item is reworded into something that reads as `[CURRENT]`.
- [ ] No disclosure or known limitation weakened or removed (ANA-17).
- [ ] Tier and rule IDs preserved.

---

## 3. Explicitly NOT done

A change is **not done** if any of these is true, regardless of test results:

- Tests pass because a test was weakened, skipped, or fitted to output.
- A semantic change was made without a version bump.
- A result can be emitted without a breakdown, fingerprint, or saturation state.
- An ambiguity was resolved silently.
- Analytical semantics changed but documentation did not.
- A new number was added whose bound sensitivity nobody has stated.
- A dependency, migration, or schema change appeared without approval.
- The diff contains unrelated changes.
- The report omits assumptions, deferred work, or risks.
- The agent cannot explain, in plain language, what the change means for the trustworthiness
  of the system's output.

That last one is the real test. If you cannot say why a security engineer should still trust
the numbers after your change, the change is not done.

---

## 4. Sign-off block

Append to every completed task:

```markdown
### Definition of Done — sign-off
G0 Scope .................... PASS / N-A / EXPLAINED
G1 Architecture ............. PASS / N-A / EXPLAINED
G2 Analytical integrity ..... PASS / N-A / EXPLAINED
G3 Security ................. PASS / N-A / EXPLAINED
G4 Tests .................... PASS / N-A / EXPLAINED
G5 Determinism .............. PASS / N-A / EXPLAINED
G6 Documentation ............ PASS / N-A / EXPLAINED
G7 Report ................... PASS / N-A / EXPLAINED

Change type: bugfix | analytic | refactor | performance | dependency | docs
Semantic change: yes (version: ____) | no
Fingerprint change: yes (comparability impact: ____) | no
Tests modified: NONE | <justification + approval reference>
Open questions raised: <ids or NONE>
```

`EXPLAINED` requires a written explanation in the report. An unexplained non-PASS means the
task is incomplete.

---

## 5. CURRENT vs FUTURE

**[CURRENT]** — §§1–4 apply now, at Phase 7A.

**[FUTURE]** — gates to be added only when the corresponding capability is authorised:
performance regression thresholds, temporal/comparability gates for snapshot features,
migration review gates, API and authorisation review gates, connector security review gates.
Do not pre-implement a gate for a capability that does not exist.
