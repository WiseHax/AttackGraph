# Path Identity & Temporal Supersession Contract



## 1. Path Identity (Phase 7A)



The identity of an `AttackPath` is determined deterministically via the `generate_canonical_path_id` function. The canonical identity is composed of the ordered sequential combination of canonical node UUIDs and canonical relationship UUIDs (edge IDs).



**Key Semantic Distinction (Parallel Edges):**

By incorporating relationship UUIDs rather than just `(source_entity, target_entity, relationship_type)`, the path identity model successfully distinguishes between parallel edges (e.g. Host A exposing Host B via both port 22 and port 443 independently).



**ETL & Temporal Constraints:**

Because path identity relies on the actual `Relationship.id` stored in PostgreSQL, the temporal stability of a path identity across snapshots depends intrinsically on the ETL ingestion pipeline.

If an ingestion run drops and recreates a logically identical relationship with a new UUID, all downstream paths utilizing that relationship will receive new identities. ETL pipelines are strictly responsible for maintaining stable Relationship UUIDs across ingestion epochs to preserve analytical path comparability.



Analytical properties such as computed risk, evidence confidence, or temporal decay explicitly do NOT alter path identity.



**Ordering of Path-ID Lists:**

Wherever a result carries a list of canonical path IDs derived from a set (e.g. `removed_path_ids` / `remaining_path_ids` in `CounterfactualRemediationResult`), the list is emitted in ascending lexicographic order of the path ID. The order is part of the result (ANA-3): serialized output is byte-identical across processes regardless of `PYTHONHASHSEED`.



## 2. Evidence Supersession Contract



AttackGraph preserves canonical facts exactly as reported by external systems.



**Append-Only Immutability:**

Canonical evidence is strictly immutable. It is never mutated in-place. Updates to a relationship's confidence or observed properties are appended as new `Evidence` records, linked via `RelationshipEvidence`.



**History vs Conflict Resolution:**

The temporal resolution system (implemented in Phase 6 as "latest timestamp wins" during `apply_decay`) is strictly a **conflict resolution** strategy used to determine which evidence record currently influences the projection.

It must not be confused with historical preservation.



Future Phase 9 snapshot functionality will rely on this append-only structure. At this stage, no bitemporal abstractions (e.g., `superseded_by_id`) have been added to the PostgreSQL schema. The current model guarantees all historical states are preserved naturally within the `Evidence` table for future time-travel queries.



## 3. Evaluation Time Contract



Evaluation time is an explicit analytical input (ANA-3). There is no fallback to the current time: `apply_decay` refuses a missing evaluation time, and `CounterfactualEngine.evaluate_candidates` requires one.

**Timezone-aware only:** evaluation times and evidence `collected_at` values must be timezone-aware. Naive datetimes are rejected (`normalize_evaluation_time`), because Python would interpret them in the host's local timezone and results would depend on where the engine runs.

**Canonical UTC:** evaluation time is normalised to UTC. Equivalent instants expressed in different timezones (e.g. `12:00+08:00` and `04:00Z`) produce identical decay decisions and byte-identical results.

**Recorded in provenance:** `AnalysisContext` (policy `AnalysisPolicyV2`, evaluation time, `AnalyticalScope`) is the single carrier of a run's inputs. `AnalysisContext.provenance()` yields an `AnalysisProvenance` record with the policy version, policy fingerprint, canonical UTC evaluation time (serialised with a `Z` suffix), and the resolved scope identity (`scope_id`, `scope_definition_version`), which is absent for an ad-hoc, non-persistable scope. Provenance is pure data: it performs no I/O and carries no engine identity.
