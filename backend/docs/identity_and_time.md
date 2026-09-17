# Path Identity & Temporal Supersession Contract



## 1. Path Identity (Phase 7A)



The identity of an `AttackPath` is determined deterministically via the `generate_canonical_path_id` function. The canonical identity is composed of the ordered sequential combination of canonical node UUIDs and canonical relationship UUIDs (edge IDs).



**Key Semantic Distinction (Parallel Edges):**

By incorporating relationship UUIDs rather than just `(source_entity, target_entity, relationship_type)`, the path identity model successfully distinguishes between parallel edges (e.g. Host A exposing Host B via both port 22 and port 443 independently).



**ETL & Temporal Constraints:**

Because path identity relies on the actual `Relationship.id` stored in PostgreSQL, the temporal stability of a path identity across snapshots depends intrinsically on the ETL ingestion pipeline.

If an ingestion run drops and recreates a logically identical relationship with a new UUID, all downstream paths utilizing that relationship will receive new identities. ETL pipelines are strictly responsible for maintaining stable Relationship UUIDs across ingestion epochs to preserve analytical path comparability.



Analytical properties such as computed risk, evidence confidence, or temporal decay explicitly do NOT alter path identity.



## 2. Evidence Supersession Contract



AttackGraph preserves canonical facts exactly as reported by external systems.



**Append-Only Immutability:**

Canonical evidence is strictly immutable. It is never mutated in-place. Updates to a relationship's confidence or observed properties are appended as new `Evidence` records, linked via `RelationshipEvidence`.



**History vs Conflict Resolution:**

The temporal resolution system (implemented in Phase 6 as "latest timestamp wins" during `apply_decay`) is strictly a **conflict resolution** strategy used to determine which evidence record currently influences the projection.

It must not be confused with historical preservation.



Future Phase 9 snapshot functionality will rely on this append-only structure. At this stage, no bitemporal abstractions (e.g., `superseded_by_id`) have been added to the PostgreSQL schema. The current model guarantees all historical states are preserved naturally within the `Evidence` table for future time-travel queries.
