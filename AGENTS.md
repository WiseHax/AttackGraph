# AGENTS.md — AttackGraph Engineering Governance Entry Point

**Audience:** any AI coding agent (Gemini, Claude, Codex, or successor) operating on this
repository, and any human reviewing that agent's work.

**Status:** normative. **Authority:** routing and process only — see the hierarchy below.

**Repository phase at time of writing:** Phases 1–6 sealed. Phase 7A in progress.

---

## 0. Read this first

If you are an AI agent and you have not read the documents in Section 3, **you are not
authorized to modify this repository.** Reading a summary of them is not reading them.

Your default posture is **conservative**. AttackGraph is a defensive security analytics
platform whose value rests entirely on the trustworthiness of its numbers. A change that
makes the system faster, prettier, or more "modern" but degrades analytical integrity is a
net negative and will be rejected.

---

## 1. What AttackGraph is

A defensive security analytics platform organised around:

```
Assets → Relationships → Evidence → Findings → Attack Paths → Risk → Remediation
```

It answers: *what can reach what, through which relationships, on what evidence, how
dangerous is it, and which defensive change reduces that risk?*

### Architectural foundations currently in place (CURRENT)

- PostgreSQL as canonical source of truth
- Rebuildable NetworkX graph projection
- `GraphStore` / `TraversalEngine` separation
- Evidence provenance
- Findings as relational entities (not graph nodes)
- Deterministic bounded traversal
- Versioned deterministic risk formulas
- Environment risk aggregation
- Counterfactual remediation analysis
- Analytical integrity and security posture
- Policy fingerprints and comparability
- Explicit saturation semantics
- Parallel-edge identity
- Immutable canonical evidence semantics

## 2. What AttackGraph is NOT

It is not, and must never become:

- an exploitation tool, offensive framework, or breach-and-attack simulator
- an autonomous agent that acts on the monitored environment
- a generic vulnerability scanner or CVE dashboard
- a machine-learned or otherwise opaque risk scorer

These are permanent prohibitions. They are not roadmap items. An agent that proposes any of
them has misunderstood the product.

---

## 3. Mandatory reading order

| # | Document | Covers |
|---|---|---|
| 1 | `docs/architecture/ARCHITECTURE_RULES.md` | Invariants, boundaries, dependency direction, canonical vs derived |
| 2 | `docs/analytics/ANALYTICAL_INTEGRITY_RULES.md` | Truth tiers, determinism, versioning, fingerprints, saturation |
| 3 | `docs/security/SECURITY_ENGINEERING_RULES.md` | Threat model, secrets, untrusted input, supply chain |
| 4 | `docs/testing/TESTING_AND_VERIFICATION.md` | Test taxonomy, golden fixtures, prohibited test edits |
| 5 | `docs/engineering/CODE_STANDARDS.md` | Determinism in code, dependencies, structure, style |
| 6 | `docs/engineering/AI_ENGINEERING_PLAYBOOK.md` | The mandatory agent workflow |
| 7 | `docs/engineering/DEFINITION_OF_DONE.md` | The gate every change must pass |

---

## 4. Source-of-truth hierarchy

When two documents appear to conflict, the **higher tier wins**. Tiers are absolute.

```
TIER 0   Explicit instruction from a human maintainer in the current task
           ↑ overrides everything below, but cannot authorise a permanent prohibition
             (Section 2 above, SEC-1, ANA-1) — those require a documented architecture change

TIER 1   docs/architecture/ARCHITECTURE_RULES.md      (structural invariants)
TIER 2   docs/security/SECURITY_ENGINEERING_RULES.md  (safety and secrets)
TIER 3   docs/analytics/ANALYTICAL_INTEGRITY_RULES.md (analysis semantics)
TIER 4   docs/testing/TESTING_AND_VERIFICATION.md     (verification)
TIER 5   docs/engineering/CODE_STANDARDS.md           (implementation style)
TIER 6   docs/engineering/DEFINITION_OF_DONE.md       (composed gate)
TIER 7   docs/engineering/AI_ENGINEERING_PLAYBOOK.md  (process)
TIER 8   AGENTS.md (this file)                        (routing)

TIER 9   Existing source code, comments, docstrings, commit messages
```

Two consequences agents get wrong:

- **Code is the lowest tier.** If the code contradicts Tier 1–5, the code is wrong or the
  rule is wrong. Both cases are a **STOP**, not a licence to "follow the existing pattern."
- **A conflict you cannot resolve by tier is a STOP.** Do not pick the interpretation that
  lets you finish. See Section 6.

Tier 2 outranks Tier 3 only on matters of safety, secrets, and untrusted input. Tier 1
outranks Tier 2 only on structural questions. If you are arguing about which applies, you
are already in a STOP condition.

---

## 5. The mandatory workflow

Every change, without exception, follows:

```
UNDERSTAND → INSPECT → PLAN → IMPLEMENT → TEST → AUDIT → REPORT
```

Full gate criteria are in `docs/engineering/AI_ENGINEERING_PLAYBOOK.md`. You may not skip,
merge, or reorder stages. You may not begin IMPLEMENT without a written PLAN in your output.

### The single most important rule in this repository

> **Never make a test pass by weakening the intended semantics of the system.**

A red test is information. Loosening an assertion, widening a bound, editing a golden
fixture, catching an exception to move on, or marking a test skipped or expected-to-fail in
order to reach green is **falsification of the verification record**. It is the most serious
process violation defined here. The correct response to a red test is in
`AI_ENGINEERING_PLAYBOOK.md` §5 and `TESTING_AND_VERIFICATION.md` §7.

---

## 6. STOP conditions

Halt work, change nothing further, and report. Do not attempt a workaround.

- S1 — A change appears to require a **database migration or schema change**.
- S2 — A change appears to require **modifying `env-risk-v1`** or introducing `env-risk-v2`.
- S3 — A change appears to require **new external dependencies**.
- S4 — A change appears to require **temporal/snapshot storage** or persisted derived artifacts.
- S5 — Documents in Tier 1–5 conflict in a way the hierarchy does not resolve.
- S6 — The task cannot be completed without violating an invariant (`ARCH-*`, `ANA-*`, `SEC-*`).
- S7 — A test fails and the only path to green is weakening a semantic assertion.
- S8 — The architecture is **ambiguous** on a point your change depends on (see §7).
- S9 — The task implies autonomous action, exploitation, or contact with a live environment.
- S10 — You would need to invent a fact about the system you cannot verify from the repo.

A STOP is a successful outcome. Reporting "I stopped at S8 because path identity inputs are
unspecified and my change depends on them" is strictly better work than guessing correctly.

---

## 7. Ambiguity is not yours to resolve

The architecture contains **known open questions** (catalogued in
`ARCHITECTURE_RULES.md` §12). Where the specification is silent, you do not choose. You:

1. Name the ambiguity precisely.
2. State which interpretations are plausible.
3. State what your change would need from each.
4. STOP (S8), or — if and only if the maintainer has pre-authorised a choice in the task —
   implement the authorised interpretation and record it in your report.

Silently resolving an ambiguity is a governance violation even when the resolution is
correct, because it makes the decision invisible to future review.

---

## 8. Hard prohibitions (summary — authoritative text lives in the linked docs)

You may not, in any change:

1. Write analytical output back into canonical storage. (ARCH-4)
2. Mutate canonical evidence. (ARCH-6)
3. Introduce nondeterminism into any analytical computation. (ANA-3)
4. Present an inferred or analytical result as observed fact. (ANA-1)
5. Emit a risk value without its breakdown. (ANA-9)
6. Emit an analytical result without its policy fingerprint. (ANA-5)
7. Suppress or omit saturation state. (ANA-7)
8. Change the meaning of a versioned analytical formula in place. (ANA-4)
9. Add machine-learned, probabilistic-opaque, or AI-generated scoring or findings. (ANA-11)
10. Add any capability that touches, probes, or acts on a real environment. (SEC-1)
11. Commit secrets, or read secrets into analytical code paths. (SEC-4)
12. Add a dependency without explicit maintainer approval. (CODE-14)
13. Modify or delete a test to achieve green. (TEST-9)
14. Perform refactors unrelated to the stated task. (AI-11)
15. Create migrations. (ARCH-14)

---

## 9. CURRENT vs FUTURE

Every rule in this document set is tagged:

- **[CURRENT]** — describes the system as it exists at Phase 7A. Binding now.
- **[FUTURE]** — describes intended direction. **Not implementable without an explicit,
  separately authorised phase.** An agent must never implement a `[FUTURE]` item because it
  appears in these documents. Presence in documentation is not authorisation.
- **[FROZEN]** — deliberately left as-is despite known limitations. Changing it requires a
  maintainer decision recorded outside your task.
- **[OPEN]** — unresolved. Triggers STOP S8 if your work depends on it.

Untagged prose is background context and is non-binding.

---

## 10. Reporting

Every task ends with a report in the format specified in `AI_ENGINEERING_PLAYBOOK.md` §7.
A change without a report is incomplete regardless of test status. The report is the
forensic record; it is read by humans and by the next agent.

---

## 11. Quick self-check before you touch anything

- [ ] I have read all seven documents in §3, not summaries of them.
- [ ] I can state which layer my change belongs to and which layers it may import from.
- [ ] I can state whether my change touches canonical truth or derived analysis.
- [ ] I know whether my change alters analytical semantics; if so, I know it needs a new version.
- [ ] I have checked my task against the STOP conditions in §6.
- [ ] I have a written PLAN.
- [ ] I am not about to add a dependency, a migration, or a test edit.
