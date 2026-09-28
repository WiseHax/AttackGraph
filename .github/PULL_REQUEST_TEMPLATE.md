<!--
Thank you for contributing. Please read CONTRIBUTING.md first.
Do not include credentials, real-environment data or undisclosed vulnerability details.
-->

## Summary

<!-- What does this change do, in one or two sentences? -->

## Motivation

<!-- Why is it needed? Link the issue or proposal. -->

## Scope

- **In scope:**
- **Explicitly out of scope:**
- **Layer(s) touched** (domain / canonical / projection / analysis / delivery):
- **Canonical data or derived analysis?**

## Tests

<!-- Exact command(s) and results. State counts before and after. -->

- Command:
- Before: collected / passed / failed / skipped
- After: collected / passed / failed / skipped
- Tests added (and what they prove):
- Tests modified: NONE <!-- any other value needs justification and maintainer approval -->

## Security considerations

<!-- Untrusted input, secrets, dependencies, Docker image, engine identity. How does the change fail closed? Write "None" only if you mean it. -->

## Documentation impact

<!-- Which docs were updated in this change? Any limitation disclosures affected? -->

## Architectural and analytical impact

- Analytical semantics changed: no / yes (new version id: )
- Policy fingerprint changed: no / yes (comparability impact: )
- Saturation behaviour:
- Determinism: <!-- how verified -->
- Invariants engaged (rule IDs):
- Ambiguities raised (not resolved):

## Checklist

- [ ] One concern per change; no unrelated refactors or reformatting
- [ ] No new dependencies, migrations or schema changes (or maintainer agreement is linked)
- [ ] No test deleted, skipped, weakened or re-baselined
- [ ] Analysis stays deterministic (no wall-clock reads, total ordering, stable tie-breaks)
- [ ] No analytical write-back to canonical storage; evidence not mutated
- [ ] Versioned formulas not changed in place; `env-risk-v1` untouched
- [ ] Results keep their breakdown, fingerprint and saturation state
- [ ] Documentation updated with the behaviour change
- [ ] No secrets, real-environment data or offensive capability
- [ ] Full test suite run; results recorded above
