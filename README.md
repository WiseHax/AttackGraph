# AttackGraph

AttackGraph is an evidence-driven attack-path and security-risk analysis platform for authorized environments.

## Overview

AttackGraph is designed to model authorized environments as security relationships and analyze potential attack paths toward critical assets. By decoupling canonical security facts from analytical graph projections, it ensures a highly reliable, explainable, and deterministic approach to defensive security analysis. 

## Core Model

Assets → Relationships → Findings → Attack Paths → Risk → Remediation

- **Assets (Entities)**: Security-relevant objects such as servers, users, databases, or cloud resources.
- **Relationships**: Directed, typed connections between assets (e.g., `CAN_AUTHENTICATE_TO`, `ROUTES_TO`).
- **Findings**: Security vulnerabilities, misconfigurations, or warnings attached to entities.
- **Attack Paths**: Discovered analytical routes an attacker could theoretically traverse from a source to a target.
- **Risk**: Deterministic, bounded calculation of the security threat posed by an attack path.
- **Remediation**: Planned mechanisms to mitigate identified risk.

*Note: Canonical security facts (Entities, Relationships, Findings, Evidence) are stored durably in the domain layer (PostgreSQL). Analytical results (Attack Paths, Risk) are never persisted as canonical security facts. The graph projection is entirely rebuildable on demand.*

## Design Principles

- **Evidence-backed analysis**: Every relationship can be traced back to independent evidence with confidence scores.
- **Deterministic analysis**: Pathfinding and risk calculations yield identical results for identical inputs.
- **Explainable risk**: Risk scores are strictly mathematical, unbounded by hidden black-box randomness.
- **Typed relationships**: Enforced canonical relationship taxonomy.
- **Truth tiers**: Strict separation between `OBSERVED` facts, `INFERRED` facts, and `ANALYTICAL` conclusions.
- **Rebuildable graph projection**: The analytical graph is a read-only topology dynamically generated from PostgreSQL.
- **Analytical results separated from canonical facts**: Analytical data never pollutes the database source of truth.
- **Defensive and authorized use**: The platform models risk strictly for defensive engineering.

## Architecture

AttackGraph implements a decoupled projection architecture:

`API / application layer → domain core → PostgreSQL canonical data → graph projection → analytical engines`

- **PostgreSQL**: Durable source of truth for all domain entities.
- **Domain Layer**: SQLAlchemy models governing strict canonical facts.
- **Graph Projection**: In-memory NetworkX analytical store populated via optimized bulk queries.
- **Analytical Engines**: Pure mathematical processors (Pathfinder, RiskEngine) that perform zero I/O.

## Current Capabilities

- canonical entities
- typed relationships
- evidence and provenance
- findings
- PostgreSQL persistence
- NetworkX graph projection
- deterministic bounded attack-path analysis
- truth-tier handling
- confidence handling
- deterministic risk calculation
- finding-aware risk amplification
- PostgreSQL integration testing

## Current Status

- Phase 1 — Complete
- Phase 2 — Complete
- Phase 3 — Complete
- Phase 4 — Complete
- Phase 5 — Planned

## Roadmap

**Phase 5 (Planned)**: Counterfactual Analysis and Remediation Ranking.

## Development

### Prerequisites

- Python 3.12+
- PostgreSQL 16 (or Docker)

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/WiseHax/AttackGraph.git
cd AttackGraph

# Set up environment variables
cp .env.example .env

# Start PostgreSQL locally
docker compose up -d postgres

# Install backend dependencies
cd backend
pip install -r requirements.txt

# Run migrations to initialize the schema
alembic upgrade head
```

## Testing

AttackGraph maintains a comprehensive unit and integration test suite.

Current verified test result: **129 tests passed.**

```bash
cd backend

# Run the full test suite
export TEST_DATABASE_URL="postgresql+asyncpg://attackgraph:YOUR_TEST_DB_PASSWORD@localhost:5432/attackgraph_test"
python -m pytest tests -v
```

## Security and Authorized Use

AttackGraph is intended strictly for authorized environments and defensive security analysis. It is a modeling platform, not an offensive exploitation tool.

## License

Licensing is to be finalized.
