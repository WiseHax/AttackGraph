"""The synthetic showcase environment.

Everything here is fictional and exists only to demonstrate the engine:
"Example Corp" is not a real organisation, hostnames use the reserved `.test`
TLD (RFC 6761), addresses come from the RFC 5737 documentation ranges, and no
credential or secret appears anywhere. The data did not come from any real
environment (SEC-6).

Identifiers are deterministic (uuid5 over a fixed namespace) and every
timestamp is fixed relative to SHOWCASE_EVALUATION_TIME, so the same fixture
always produces the same canonical records and the same analysis.

The fixture is plain data plus one loader that writes it through the
canonical repositories; tests reuse both.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Entity, Evidence, Finding, Relationship, Scope, ScopeDefinition
from app.storage.repositories import (
    EntityRepository,
    EvidenceRepository,
    FindingRepository,
    RelationshipRepository,
    ScopeDefinitionRepository,
    ScopeRepository,
)

# Fixed namespace for all showcase identifiers. Changing it changes every ID.
SHOWCASE_NAMESPACE = uuid.UUID("6a1c3f0e-5b2d-4c8e-9f7a-3d2b1e0c9a84")

# The single evaluation time of the showcase analysis (ANA-3). Evidence ages
# are expressed relative to it, so decay decisions are fixed.
SHOWCASE_EVALUATION_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

# When the synthetic records were "imported". Only used to keep canonical
# timestamps deterministic; it plays no role in the analysis.
SHOWCASE_IMPORT_TIME = SHOWCASE_EVALUATION_TIME - timedelta(hours=1)


def showcase_id(kind: str, key: str) -> uuid.UUID:
    """Deterministic identifier for a showcase record."""
    return uuid.uuid5(SHOWCASE_NAMESPACE, f"attackgraph-showcase:{kind}:{key}")


@dataclass(frozen=True)
class EntitySpec:
    key: str
    entity_type: str
    name: str
    description: str
    criticality: str | None = None
    exposure: str | None = None
    address: str | None = None

    @property
    def id(self) -> uuid.UUID:
        return showcase_id("entity", self.key)


@dataclass(frozen=True)
class EvidenceSpec:
    key: str
    source: str
    source_type: str
    assertion: str
    age: timedelta
    confidence: str
    freshness_ttl_seconds: int | None
    record: str

    @property
    def id(self) -> uuid.UUID:
        return showcase_id("evidence", self.key)

    @property
    def collected_at(self) -> datetime:
        return SHOWCASE_EVALUATION_TIME - self.age


@dataclass(frozen=True)
class RelationshipSpec:
    key: str
    source: str
    relationship_type: str
    target: str
    truth_tier: str
    description: str
    evidence: tuple[str, ...] = ()

    @property
    def id(self) -> uuid.UUID:
        return showcase_id("relationship", self.key)


@dataclass(frozen=True)
class FindingSpec:
    key: str
    entity: str
    title: str
    severity: str
    description: str
    evidence: tuple[str, ...] = ()

    @property
    def id(self) -> uuid.UUID:
        return showcase_id("finding", self.key)


@dataclass(frozen=True)
class ShowcaseFixture:
    organisation: str
    scope_display_name: str
    source_entity: str
    target_entity: str
    entities: tuple[EntitySpec, ...]
    evidence: tuple[EvidenceSpec, ...]
    relationships: tuple[RelationshipSpec, ...]
    findings: tuple[FindingSpec, ...]
    notes: tuple[str, ...] = field(default=())

    @property
    def scope_id(self) -> uuid.UUID:
        return showcase_id("scope", "example-corp")

    def entity(self, key: str) -> EntitySpec:
        return {e.key: e for e in self.entities}[key]

    def relationship(self, key: str) -> RelationshipSpec:
        return {r.key: r for r in self.relationships}[key]


_DAY = timedelta(days=1)
_HOUR = timedelta(hours=1)

SHOWCASE_FIXTURE = ShowcaseFixture(
    organisation="Example Corp (synthetic)",
    scope_display_name="Example Corp showcase (synthetic)",
    source_entity="internet",
    target_entity="customer-db",
    entities=(
        EntitySpec("internet", "INTERNET", "Internet",
                   "Untrusted external networks; the modelled starting point.",
                   exposure="EXTERNAL"),
        EntitySpec("storefront", "APPLICATION", "storefront.example.test",
                   "Public web storefront.",
                   criticality="MEDIUM", exposure="EXTERNAL", address="203.0.113.20"),
        EntitySpec("vpn-gateway", "HOST", "vpn.example.test",
                   "Remote-access VPN gateway.",
                   criticality="HIGH", exposure="EXTERNAL", address="203.0.113.10"),
        EntitySpec("web-server", "SERVER", "web-01.corp.example.test",
                   "Application server behind the storefront.",
                   criticality="MEDIUM", exposure="INTERNAL", address="192.0.2.21"),
        EntitySpec("payments-api", "API", "payments-api.corp.example.test",
                   "Internal payments API.",
                   criticality="HIGH", exposure="INTERNAL", address="192.0.2.31"),
        EntitySpec("corp-network", "NETWORK_SEGMENT", "corp-lan (198.51.100.0/24)",
                   "Internal corporate network segment reachable from the VPN.",
                   exposure="INTERNAL"),
        EntitySpec("jump-host", "HOST", "jump-01.corp.example.test",
                   "Administrative jump host.",
                   criticality="HIGH", exposure="RESTRICTED", address="198.51.100.5"),
        EntitySpec("ci-runner", "SERVER", "ci-runner-01.corp.example.test",
                   "Continuous-integration runner used for production deployments.",
                   criticality="HIGH", exposure="INTERNAL", address="198.51.100.40"),
        EntitySpec("source-repo", "REPOSITORY", "git.corp.example.test/platform/deploy",
                   "Deployment configuration repository.",
                   criticality="HIGH", exposure="INTERNAL"),
        EntitySpec("dev-laptop", "WORKSTATION", "laptop-dev-07.corp.example.test",
                   "Engineering workstation.",
                   criticality="MEDIUM", exposure="INTERNAL", address="198.51.100.77"),
        EntitySpec("alice", "USER", "alice (synthetic database engineer)",
                   "Fictional engineer account used for database administration."),
        EntitySpec("svc-storefront", "SERVICE_ACCOUNT", "svc-storefront",
                   "Service identity of the storefront application."),
        EntitySpec("svc-deploy", "SERVICE_ACCOUNT", "svc-deploy",
                   "Deployment service identity."),
        EntitySpec("db-admins", "GROUP", "db-admins",
                   "Directory group of database administrators."),
        EntitySpec("prod-db-admin", "ROLE", "prod-db-admin",
                   "Cloud role with administrative rights on the production database."),
        EntitySpec("customer-db", "DATABASE", "customer-db.corp.example.test",
                   "Production database holding (fictional) customer records.",
                   criticality="CRITICAL", exposure="RESTRICTED", address="192.0.2.50"),
    ),
    evidence=(
        EvidenceSpec("fw-perimeter", "synthetic-firewall-export", "firewall_config",
                     "Perimeter rules allow inbound HTTPS to the storefront and VPN gateway.",
                     age=2 * _DAY, confidence="HIGH", freshness_ttl_seconds=30 * 86400,
                     record="fw-perimeter-ruleset-2026-01-13"),
        EvidenceSpec("lb-config", "synthetic-load-balancer-export", "load_balancer_config",
                     "Storefront load balancer forwards requests to web-01.",
                     age=2 * _DAY, confidence="HIGH", freshness_ttl_seconds=30 * 86400,
                     record="lb-storefront-pool"),
        EvidenceSpec("k8s-manifest", "synthetic-cluster-inventory", "workload_manifest",
                     "Storefront workload runs under the svc-storefront identity.",
                     age=1 * _DAY, confidence="HIGH", freshness_ttl_seconds=14 * 86400,
                     record="deployment/storefront"),
        EvidenceSpec("iam-export", "synthetic-iam-export", "identity_policy",
                     "Identity policy export: role bindings and assume-role grants.",
                     age=1 * _DAY, confidence="HIGH", freshness_ttl_seconds=7 * 86400,
                     record="iam-snapshot-2026-01-14"),
        EvidenceSpec("netflow-payments", "synthetic-flow-logs", "network_flow",
                     "Flow logs show web-01 and the storefront identity calling the payments API.",
                     age=6 * _HOUR, confidence="MEDIUM", freshness_ttl_seconds=3 * 86400,
                     record="flows-payments-api-24h"),
        EvidenceSpec("app-config-payments", "synthetic-config-scan", "application_config",
                     "Payments API configuration declares its dependency on customer-db.",
                     age=3 * _DAY, confidence="HIGH", freshness_ttl_seconds=30 * 86400,
                     record="payments-api/config.yaml"),
        EvidenceSpec("vpn-config", "synthetic-vpn-export", "vpn_config",
                     "VPN profile routes authenticated clients into corp-lan.",
                     age=2 * _DAY, confidence="HIGH", freshness_ttl_seconds=30 * 86400,
                     record="vpn-profile-engineering"),
        EvidenceSpec("fw-internal", "synthetic-firewall-export", "firewall_config",
                     "Internal rules allow web-01 into corp-lan, and corp-lan to reach the jump host, "
                     "laptops and CI runner.",
                     age=2 * _DAY, confidence="HIGH", freshness_ttl_seconds=30 * 86400,
                     record="fw-internal-ruleset-2026-01-13"),
        EvidenceSpec("ssh-audit-old", "synthetic-ssh-config-audit", "ssh_config",
                     "Earlier audit: SSH key for the CI runner not found on the jump host.",
                     age=40 * _DAY, confidence="LOW", freshness_ttl_seconds=90 * 86400,
                     record="ssh-audit-2025-12-06"),
        EvidenceSpec("ssh-audit-new", "synthetic-ssh-config-audit", "ssh_config",
                     "Current audit: jump host holds an authorised SSH key for the CI runner.",
                     age=3 * _DAY, confidence="HIGH", freshness_ttl_seconds=90 * 86400,
                     record="ssh-audit-2026-01-12"),
        EvidenceSpec("ci-config", "synthetic-ci-inventory", "ci_config",
                     "CI runner executes deployment jobs as svc-deploy.",
                     age=1 * _DAY, confidence="HIGH", freshness_ttl_seconds=14 * 86400,
                     record="ci/runner-01.toml"),
        EvidenceSpec("git-credential-scan", "synthetic-endpoint-telemetry", "credential_inventory",
                     "laptop-dev-07 caches a git credential with write access to the deploy repo.",
                     age=2 * _DAY, confidence="MEDIUM", freshness_ttl_seconds=14 * 86400,
                     record="credential-inventory-laptop-dev-07"),
        EvidenceSpec("secret-scan", "synthetic-secret-scan", "secret_scan",
                     "Secret scanning flags a svc-deploy token committed to the deploy repo.",
                     age=4 * _DAY, confidence="MEDIUM", freshness_ttl_seconds=30 * 86400,
                     record="secret-scan-finding-0042"),
        EvidenceSpec("db-grants", "synthetic-database-grants-export", "database_grants",
                     "Database grants: prod-db-admin and db-admins hold administrative rights.",
                     age=1 * _DAY, confidence="HIGH", freshness_ttl_seconds=14 * 86400,
                     record="customer-db-grants-2026-01-14"),
        EvidenceSpec("edr-session", "synthetic-endpoint-telemetry", "endpoint_session",
                     "Endpoint telemetry shows alice logged in on laptop-dev-07.",
                     age=20 * _DAY, confidence="HIGH", freshness_ttl_seconds=7 * 86400,
                     record="edr-session-snapshot-2025-12-26"),
        EvidenceSpec("directory-export", "synthetic-directory-export", "directory_membership",
                     "Directory export lists alice as a member of db-admins.",
                     age=1 * _DAY, confidence="HIGH", freshness_ttl_seconds=14 * 86400,
                     record="directory-groups-2026-01-14"),
        EvidenceSpec("vuln-scan", "synthetic-vulnerability-scan", "vulnerability_scan",
                     "Authenticated vulnerability scan of internal hosts.",
                     age=2 * _DAY, confidence="HIGH", freshness_ttl_seconds=14 * 86400,
                     record="vuln-scan-2026-01-13"),
    ),
    relationships=(
        RelationshipSpec("internet-routes-storefront", "internet", "ROUTES_TO", "storefront", "OBSERVED",
                         "Inbound HTTPS from the internet reaches the storefront.",
                         evidence=("fw-perimeter",)),
        RelationshipSpec("internet-routes-vpn", "internet", "ROUTES_TO", "vpn-gateway", "OBSERVED",
                         "Inbound VPN connections from the internet reach the gateway.",
                         evidence=("fw-perimeter",)),
        RelationshipSpec("storefront-runs-as-svc", "storefront", "RUNS_AS", "svc-storefront", "OBSERVED",
                         "The storefront process runs as svc-storefront.",
                         evidence=("k8s-manifest",)),
        RelationshipSpec("svc-storefront-permission-payments", "svc-storefront", "HAS_PERMISSION_ON",
                         "payments-api", "OBSERVED",
                         "svc-storefront may call the payments API.",
                         evidence=("iam-export", "netflow-payments")),
        RelationshipSpec("storefront-routes-web", "storefront", "ROUTES_TO", "web-server", "OBSERVED",
                         "The storefront load balancer forwards traffic to web-01.",
                         evidence=("lb-config",)),
        RelationshipSpec("web-communicates-payments", "web-server", "COMMUNICATES_WITH", "payments-api",
                         "OBSERVED", "web-01 calls the payments API.",
                         evidence=("netflow-payments",)),
        RelationshipSpec("web-runs-as-svc-deploy", "web-server", "RUNS_AS", "svc-deploy", "INFERRED",
                         "Inferred by rule: the deployment agent on web-01 runs as svc-deploy "
                         "(no direct observation)."),
        RelationshipSpec("payments-depends-on-db", "payments-api", "DEPENDS_ON", "customer-db", "OBSERVED",
                         "The payments API depends on customer-db.",
                         evidence=("app-config-payments",)),
        RelationshipSpec("vpn-routes-corp", "vpn-gateway", "ROUTES_TO", "corp-network", "OBSERVED",
                         "The VPN places clients on corp-lan.",
                         evidence=("vpn-config",)),
        RelationshipSpec("web-routes-corp", "web-server", "ROUTES_TO", "corp-network", "OBSERVED",
                         "web-01 can reach corp-lan (no segmentation between the web tier and corp-lan).",
                         evidence=("fw-internal",)),
        RelationshipSpec("corp-routes-jump", "corp-network", "ROUTES_TO", "jump-host", "OBSERVED",
                         "corp-lan can reach the jump host.",
                         evidence=("fw-internal",)),
        RelationshipSpec("corp-routes-laptop", "corp-network", "ROUTES_TO", "dev-laptop", "OBSERVED",
                         "corp-lan can reach engineering laptops.",
                         evidence=("fw-internal",)),
        RelationshipSpec("jump-auth-ci", "jump-host", "CAN_AUTHENTICATE_TO", "ci-runner", "OBSERVED",
                         "The jump host holds an SSH key accepted by the CI runner.",
                         evidence=("ssh-audit-old", "ssh-audit-new")),
        RelationshipSpec("jump-routes-ci", "jump-host", "ROUTES_TO", "ci-runner", "OBSERVED",
                         "The jump host has network reachability to the CI runner "
                         "(parallel to the authentication relationship).",
                         evidence=("fw-internal",)),
        RelationshipSpec("ci-runs-as-svc-deploy", "ci-runner", "RUNS_AS", "svc-deploy", "OBSERVED",
                         "Deployment jobs on the CI runner execute as svc-deploy.",
                         evidence=("ci-config",)),
        RelationshipSpec("laptop-auth-repo", "dev-laptop", "CAN_AUTHENTICATE_TO", "source-repo", "OBSERVED",
                         "A git credential cached on laptop-dev-07 can write to the deploy repository.",
                         evidence=("git-credential-scan",)),
        RelationshipSpec("repo-stores-svc-deploy", "source-repo", "STORES", "svc-deploy", "OBSERVED",
                         "The deploy repository stores a svc-deploy token.",
                         evidence=("secret-scan",)),
        RelationshipSpec("svc-deploy-assume-db-admin", "svc-deploy", "CAN_ASSUME", "prod-db-admin",
                         "OBSERVED", "svc-deploy is allowed to assume the prod-db-admin role.",
                         evidence=("iam-export",)),
        RelationshipSpec("db-admin-permission-db", "prod-db-admin", "HAS_PERMISSION_ON", "customer-db",
                         "OBSERVED", "prod-db-admin has administrative rights on customer-db.",
                         evidence=("db-grants",)),
        RelationshipSpec("laptop-runs-as-alice", "dev-laptop", "RUNS_AS", "alice", "OBSERVED",
                         "alice has an interactive session on laptop-dev-07 (stale observation).",
                         evidence=("edr-session",)),
        RelationshipSpec("alice-member-db-admins", "alice", "MEMBER_OF", "db-admins", "OBSERVED",
                         "alice is a member of db-admins.",
                         evidence=("directory-export",)),
        RelationshipSpec("db-admins-permission-db", "db-admins", "HAS_PERMISSION_ON", "customer-db",
                         "OBSERVED", "db-admins has administrative rights on customer-db.",
                         evidence=("db-grants",)),
    ),
    findings=(
        FindingSpec("storefront-tls", "storefront", "Legacy TLS protocol versions enabled", "MEDIUM",
                    "Synthetic finding: the storefront still negotiates deprecated TLS versions.",
                    evidence=("vuln-scan",)),
        FindingSpec("web-unpatched", "web-server", "Application server missing security updates", "HIGH",
                    "Synthetic finding: web-01 runs an application server release with published "
                    "security fixes outstanding.",
                    evidence=("vuln-scan",)),
        FindingSpec("jump-password-auth", "jump-host", "Password authentication enabled for SSH", "HIGH",
                    "Synthetic finding: the jump host accepts password logins.",
                    evidence=("vuln-scan",)),
        FindingSpec("ci-long-lived-token", "ci-runner", "Long-lived deployment token on runner", "HIGH",
                    "Synthetic finding: the runner caches a non-expiring svc-deploy token.",
                    evidence=("secret-scan",)),
        FindingSpec("db-audit-disabled", "customer-db", "Database audit logging disabled", "LOW",
                    "Synthetic finding: administrative actions on customer-db are not audited.",
                    evidence=("vuln-scan",)),
    ),
    notes=(
        "Every name, address and record in this environment is fictional.",
        "Hostnames use the reserved .test TLD; addresses come from RFC 5737 documentation ranges.",
    ),
)


@dataclass(frozen=True)
class LoadedShowcase:
    """Canonical identity of the fixture after loading."""

    scope_id: uuid.UUID
    definition_version: int


async def load_showcase_fixture(
    session: AsyncSession, fixture: ShowcaseFixture = SHOWCASE_FIXTURE
) -> LoadedShowcase:
    """Write the fixture through the canonical repositories (flush only, no commit)."""
    stamp = SHOWCASE_IMPORT_TIME

    entities = EntityRepository(session)
    for spec in fixture.entities:
        await entities.create(Entity(
            id=spec.id,
            entity_type=spec.entity_type,
            name=spec.name,
            description=spec.description,
            criticality=spec.criticality,
            exposure=spec.exposure,
            owner=fixture.organisation,
            canonical_key=f"showcase:{spec.entity_type.lower()}:{spec.key}",
            metadata_={"synthetic": True, **({"address": spec.address} if spec.address else {})},
            created_at=stamp,
            updated_at=stamp,
        ))

    evidence = EvidenceRepository(session)
    for spec in fixture.evidence:
        await evidence.create(Evidence(
            id=spec.id,
            source=spec.source,
            source_type=spec.source_type,
            assertion=spec.assertion,
            collected_at=spec.collected_at,
            imported_at=stamp,
            confidence=spec.confidence,
            freshness_ttl_seconds=spec.freshness_ttl_seconds,
            raw_reference={"synthetic": True, "record": spec.record},
            created_at=stamp,
        ))

    entity_ids = {spec.key: spec.id for spec in fixture.entities}
    evidence_ids = {spec.key: spec.id for spec in fixture.evidence}

    relationships = RelationshipRepository(session)
    for spec in fixture.relationships:
        await relationships.create(
            Relationship(
                id=spec.id,
                source_entity_id=entity_ids[spec.source],
                target_entity_id=entity_ids[spec.target],
                relationship_type=spec.relationship_type,
                truth_tier=spec.truth_tier,
                metadata_={"synthetic": True, "description": spec.description},
                created_at=stamp,
                updated_at=stamp,
            ),
            evidence_ids=[evidence_ids[key] for key in spec.evidence],
        )

    findings = FindingRepository(session)
    for spec in fixture.findings:
        await findings.create(
            Finding(
                id=spec.id,
                entity_id=entity_ids[spec.entity],
                title=spec.title,
                description=spec.description,
                severity=spec.severity,
                source="synthetic-vulnerability-scan",
                source_type="vulnerability_scanner",
                confidence="HIGH",
                status="open",
                created_at=stamp,
                updated_at=stamp,
            ),
            evidence_ids=[evidence_ids[key] for key in spec.evidence],
        )

    scope = await ScopeRepository(session).create(Scope(
        id=fixture.scope_id,
        display_name=fixture.scope_display_name,
        created_at=stamp,
        updated_at=stamp,
    ))
    definition = await ScopeDefinitionRepository(session).create(
        scope.id,
        ScopeDefinition(input_boundary_kind="UNIVERSAL", reporting_selector="ALL", created_at=stamp),
    )
    return LoadedShowcase(scope_id=scope.id, definition_version=definition.version)
