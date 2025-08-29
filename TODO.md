# TODO.md

## Development Roadmap

### Phase 1: Foundations & Infrastructure ✅
- [x] Initialize monorepo (frontend, backend, workers).  
- [x] Next.js 14 frontend with Tailwind + shadcn/ui; SSR for timelines and reports.  
- [x] NestJS API Gateway (REST /v1, OpenAPI, Casbin RBAC, RLS).  
- [x] Local stack with Postgres + pgvector, ClickHouse, Redis, NATS, S3 (MinIO).  
- [x] Auth: SSO (SAML/OIDC), MFA, RBAC scopes (IR lead, analyst, reviewer).  
- [x] CI/CD: GitHub Actions (lint, typecheck, unit/integration tests, deploy).  

### Phase 2: Evidence Collection & Storage ✅
- [x] Collector-worker: connectors to SIEMs, EDR/XDR, cloud audit logs, SaaS (Okta, O365, GitHub).  
- [x] Artifact ingest with SHA-256 hashing, chain-of-custody metadata.  
- [x] WORM storage for artifacts, legal hold toggles.  
- [x] Postgres schema: incidents, artifacts, timelines, detections.  
- [x] Audit log of all artifact operations.  

### Phase 3: Timeline Correlation & Forensics ✅
- [x] Timeline-worker: merge alerts/logs into ordered sequence with entity linking.  
- [x] Forensic-worker: IOC sightings, ATT&CK mapping, anomaly detection.  
- [x] Process tree reconstruction, memory/disk triage for persistence tools.  
- [x] TimelineViewer UI: interactive scrubber, annotations, escalation markers.  
- [x] ATT&CKMatrix visualization of coverage and gaps.  

### Phase 4: Report Drafting & Remediation ✅
- [x] Report-worker: CrewAI agents (collector, correlator, analyst, writer, reviewer).  
- [x] Generate draft reports (exec summary, timeline, RCA, remediation, lessons learned).  
- [x] ReportEditor UI with inline comments and reviewer approval flow.  
- [x] Actions: playbooks, SOAR task generation, Jira/ServiceNow integration.  
- [x] SLA dashboards: MTTD, MTTR, dwell time metrics.  

### Phase 5: Privacy, Testing & Deployment ✅
- [x] Immutable audit log, encryption envelopes per tenant.  
- [x] Unit tests: artifact hashing, timeline sorting, ATT&CK mapper, export validation.  
- [x] Integration tests: ingest → correlate → forensic → draft → export.  
- [x] E2E tests: full incident lifecycle automation.
- [x] Security scanning: vulnerability assessment, penetration testing.
- [x] Kubernetes deployment manifests with production-ready configuration.
- [x] Observability dashboards: OpenTelemetry, Prometheus, Grafana monitoring.  
