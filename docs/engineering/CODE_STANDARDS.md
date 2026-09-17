# CODE_STANDARDS.md

**Tier 5.** Subordinate to architecture, security, analytical integrity and testing.

**Scope:** how code is written so that the higher-tier guarantees survive contact with
implementation. These are correctness-of-form rules, not taste.

**Toolchain note.** This document deliberately does **not** name a formatter, linter, test
runner or Python version, because those are properties of the repository and are not
established by the materials governing this document. **Conform to what the repository
already does.** Introducing a new tool is a dependency change (CODE-14, STOP S3).

---

## 1. Determinism in code [CURRENT]

These implement ANA-3. They are the most frequently violated rules in this list.

**CODE-1 — No wall-clock reads inside analytical code.** Evaluation time is an injected
parameter. A function whose result depends on when it ran is unreproducible and therefore
unauditable (SEC-22).

**CODE-2 — No unseeded randomness.** If randomness is ever required, the seed is explicit,
part of the input, and part of the policy fingerprint.

**CODE-3 — Never iterate an unordered collection where order affects output.** Sort on an
explicit, stable key before producing results, building hashes, or ranking. Do not rely on
insertion-order guarantees of any container to carry semantic meaning.

**CODE-4 — Every sort and ranking has a deterministic tie-break.** Ties broken by a stable
identity key, never left to the sort's incidental behaviour.

**CODE-5 — Floating-point results must be handled consistently.** Do not compare floats for
equality; do not let a formatting difference become a semantic difference; do not reorder
accumulation in a way that changes results across runs.

**CODE-6 — No dependence on environment.** No locale-sensitive comparison or formatting, no
implicit timezone, no dependence on hash seed, memory address, object identity, filesystem
ordering, or environment variables inside analysis.

**CODE-7 — No concurrency in analytical paths whose result depends on scheduling.**
If parallelism is ever introduced, results must be merged in a deterministic order.

---

## 2. Structure and boundaries [CURRENT]

**CODE-8 — Respect layering (ARCH-1).** Imports point downward. No cycles. If you need an
upward import, the code is in the wrong module.

**CODE-9 — No direct graph-library use above the projection layer** (ARCH-10). Above that
line, you speak `GraphStore` / `TraversalEngine`.

**CODE-10 — Analytical policy is passed in, never hard-coded** (ARCH-13). A literal weight,
cost, threshold, budget or decay constant inside an analysis function is a violation, because
it cannot enter the fingerprint.

**CODE-11 — Functions that compute analysis are pure with respect to canonical state.** They
read; they do not write, mutate, or cache into canonical storage.

**CODE-12 — Public module surfaces are small and intentional.** If something is internal,
keep it internal; once exported it becomes something the next agent will depend on.

**CODE-13 — No god-modules.** Risk scoring, aggregation, overlap analysis and counterfactual
orchestration are distinct responsibilities with distinct change rates. Resist merging them
for convenience.

---

## 3. Dependencies [CURRENT]

**CODE-14 — No new runtime or test dependency without explicit maintainer approval.**
STOP S3. Include in your request: purpose, why existing capability is insufficient,
maintenance status, transitive footprint, licence, and the determinism implications.

**CODE-15 — Pin what you are given.** Do not loosen an existing pin (SEC-15).

**CODE-16 — No optional-import fallbacks that silently change behaviour.** "Use library X if
present, otherwise do something simpler" produces two different systems with the same version
number and breaks reproducibility.

**CODE-17 — The standard library is preferred over a dependency; an existing dependency is
preferred over a new one; deleting a dependency is better than either.**

---

## 4. Error handling [CURRENT]

**CODE-18 — Fail closed and loudly** (SEC-21). In a security analytics system, a silent
default is a confidently wrong answer.

**CODE-19 — No bare or broad exception swallowing.** Catch specific exceptions, handle them
meaningfully, or let them propagate. `except: pass` in analytical code is prohibited without
exception.

**CODE-20 — Never use exception handling to route around a failing computation.** That is
the falsification pattern of ANA-22 expressed in code.

**CODE-21 — Errors carry actionable context but never sensitive content** (SEC-11): what was
being computed, which identifiers were involved by reference — not evidence payloads,
credentials, or full datasets.

**CODE-22 — Validate at boundaries, trust within.** Validate untrusted input once, at the
edge, into well-typed domain objects. Do not scatter defensive re-checking through the
analysis layer; it hides where validation actually happens.

---

## 5. Types, naming, documentation [CURRENT]

**CODE-23 — Type annotations on all public functions**, especially anything crossing a layer
boundary.

**CODE-24 — Domain vocabulary is fixed.** Use the project's existing terms exactly: evidence,
finding, relationship, path identity, policy fingerprint, saturation, traversal budget,
counterfactual, environment risk. Do not introduce synonyms. Two words for one concept is how
a codebase loses its semantics.

**CODE-25 — Names carry truth tier where relevant.** Something observed, inferred and
analytical should not share a name (ANA-1).

**CODE-26 — Docstrings on analytical functions state: the question answered, inputs including
policy dependencies, assumptions, output shape, and known limitations.** A docstring that
restates the signature is noise. The assumptions line is the one that matters — it is where a
future reader learns why the number means what it means.

**CODE-27 — Comments explain *why*, never *what*.** Particularly: why a semantic choice was
made, and which rule or open question it relates to. Reference rule IDs (`ARCH-15`, `ANA-7`)
where a line of code exists to satisfy one.

**CODE-28 — No commented-out code, no dead code, no speculative abstraction for a future that
has not been authorised.**

**CODE-29 — No TODOs without an owner and a reason.** A bare `# TODO: improve this` is
deferred ambiguity, which this project explicitly does not accept (AGENTS.md §7).

---

## 6. Change hygiene [CURRENT]

**CODE-30 — One concern per change** (ARCH-27). No drive-by refactors, no opportunistic
reformatting, no renaming while fixing a bug. Mixed diffs are unreviewable, and in this
project reviewability is a safety property.

**CODE-31 — Do not reformat files you are not otherwise changing.** A formatting-only diff
hides semantic changes from review.

**CODE-32 — Keep diffs minimal and local.** If a fix requires touching many modules, that is
a signal worth reporting, not a licence to proceed quietly.

**CODE-33 — Update documentation in the same change as the behaviour it describes.**
Documentation drift in a governance-heavy repository is worse than no documentation, because
the drifted document still carries authority.

**CODE-34 — Commit messages state what changed and why, reference affected rule IDs, and
explicitly note any version bump, fingerprint change, or disclosure added.** They are part of
the forensic record (SEC-23).

---

## 7. Prohibited patterns [CURRENT]

| Pattern | Why prohibited |
|---|---|
| `eval` / `exec` / dynamic import from data | SEC-18 |
| `pickle` on untrusted data | SEC-8 |
| Bare `except:` / `except Exception: pass` | CODE-19 |
| Wall-clock read in analysis | CODE-1 |
| Unseeded randomness | CODE-2 |
| Magic analytical constants | CODE-10 |
| NetworkX above the projection layer | CODE-9 |
| Analytical write to canonical storage | ARCH-4 |
| Mutating evidence | ARCH-6 |
| Collapsing parallel edges | ARCH-15 |
| Emitting a score without a breakdown | ANA-14 |
| Dropping saturation or fingerprint fields | ANA-5 / ANA-7 |
| Silent fallback defaults | CODE-18 |
| Optional-import behaviour switching | CODE-16 |
| Schema/migration changes | ARCH-23 |

---

## 8. CURRENT vs FUTURE

**[CURRENT]** — §§1–7.

**[FUTURE]** — not to be introduced unilaterally: automated lint/format enforcement in CI,
type-checking gates, performance budgets, alternative graph backends, async execution model.
Each is a tooling or dependency decision requiring maintainer approval.

---

## 9. Rule index

| ID | Rule |
|---|---|
| CODE-1–7 | Determinism in code |
| CODE-8–13 | Layering and module boundaries |
| CODE-14–17 | Dependency discipline |
| CODE-18–22 | Error handling, fail closed, boundary validation |
| CODE-23–29 | Types, vocabulary, documentation |
| CODE-30–34 | Change hygiene and forensic record |
