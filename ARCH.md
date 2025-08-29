# ARCH.md

## System Architecture — AI Incident Response Copilot

### High-Level Diagram
```
Frontend (Next.js 14 + React 18)
   | REST / SSE
   v
API Gateway (NestJS)
   | NATS / gRPC
   v
CrewAI Orchestrator (Python + FastAPI)
   |-> collector-worker (connectors, artifacts)
   |-> timeline-worker (correlation, entity linking)
   |-> forensic-worker (IOC mapping, anomaly scans)
   |-> report-worker (draft generation)
   |-> export-worker (PDF/JSON/Markdown/STIX)
   |
   +-- Postgres (pgvector: incidents/artifacts/timelines/reports)
   +-- ClickHouse (logs/events)
   +-- Redis (state/cache/queues)
   +-- S3/R2 (artifacts, reports)
```

### Frontend (Next.js + React)
- **Incident dashboards**: list and manage incidents.  
- **TimelineViewer**: correlated events with scrub & zoom.  
- **ReportEditor**: AI drafts with inline comments.  
- **ArtifactCard**: immutable evidence with SHA-256 hashes.  
- **ActionBoard**: playbooks and tasks.  
- **ExportWizard**: PDF/JSON/STIX/Markdown outputs.  
- **UI**: Tailwind + shadcn/ui with cinematic visuals.  

### Backend (NestJS)
- REST /v1 with OpenAPI 3.1.  
- Casbin RBAC, RLS by org_id.  
- Idempotency-Key, Problem+JSON errors.  
- SSE for long-running report and correlation jobs.  

### Workers & Orchestrator (Python CrewAI + FastAPI)
- **collector-worker**: connectors, artifact hashing/storage.  
- **timeline-worker**: correlation of alerts, logs, comms, actions.  
- **forensic-worker**: IOC sightings, ATT&CK mapping, anomaly detection.  
- **report-worker**: CrewAI agents orchestrating draft postmortems.  
- **export-worker**: builds PDFs, JSON, STIX/TAXII, Markdown, evidence tarballs.  

### Eventing
- **NATS Subjects**: `incident.collect`, `timeline.build`, `forensic.run`, `report.draft`, `export.make`.  
- **Redis Streams**: progress tracking, SSE to frontend.  

### Data Layer
- **Postgres 16 + pgvector**: incidents, artifacts, timelines, detections, reports, actions.  
- **ClickHouse**: scalable event/log storage.  
- **Redis**: caching, queues, session state.  
- **S3/R2**: WORM storage for evidence, exports.  
- **Encryption**: Cloud KMS with per-tenant envelopes.  

### Observability & Security
- **Tracing**: OpenTelemetry.  
- **Metrics**: Prometheus + Grafana.  
- **Errors**: Sentry.  
- **Security**: SSO/MFA, immutable audit logs, RLS, regional data residency.  

### DevOps & Deployment
- **Frontend**: Vercel.  
- **Backend**: GKE/Fly/Render, GPU nodes for CrewAI orchestration.  
- **CI/CD**: GitHub Actions (lint, tests, deploy, image scan).  
- **Data**: PITR backups, replication.  
