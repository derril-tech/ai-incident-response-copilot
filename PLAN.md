# PLAN.md

## Product: AI Incident Response Copilot

### Vision & Goals
Automate **incident retrospectives** using CrewAI multi-agent orchestration to collect evidence, correlate timelines, perform forensic analysis, and generate draft post-incident reports with remediation steps and audit trails.

### Key Objectives
- Collect and hash incident evidence (logs, pcaps, memory dumps, forensic artifacts).  
- Correlate events into a timeline with linked entities and annotations.  
- Run forensic analysis: IOC sightings, ATT&CK mapping, anomaly scans.  
- Generate draft post-incident reports with CrewAI agents (collector, correlator, analyst, writer, reviewer).  
- Export reports in multiple formats and integrate tasks into Jira/ServiceNow.  
- Provide immutable audit logs and SLA dashboards.  

### Target Users
- Incident Response teams (IR, CERT/SOC).  
- Security leadership (CISOs) needing executive-ready postmortems.  
- Forensic analysts creating chain-of-custody packages.  
- Compliance/GRC teams tracking remediation and audits.  

### High-Level Approach
1. **Frontend (Next.js 14 + React 18)**  
   - Evidence uploads, incident dashboards, timeline visualizer.  
   - Report editor for draft AI reports.  
   - SLA and ATT&CK coverage dashboards.  
   - Tailwind + shadcn/ui with professional, cinematic styling.  

2. **Backend (NestJS + Python CrewAI Workers)**  
   - API Gateway with REST /v1, OpenAPI, RBAC, RLS.  
   - CrewAI orchestrator to manage collector, correlator, forensic, report, and reviewer agents.  
   - Workers for artifact collection, timeline building, forensic analysis, report drafting, and exports.  
   - Postgres + pgvector, ClickHouse for high-volume logs, S3/R2 for artifact storage.  

3. **DevOps & Security**  
   - Vercel (frontend), GKE/Fly/Render (backend).  
   - WORM storage for evidence.  
   - Observability: OpenTelemetry, Prometheus, Grafana, Sentry.  
   - Security: MFA, SSO, RLS, immutable audit logs.  

### Success Criteria
- **Product KPIs**:  
  - Reduce time-to-draft report by ≥ 60%.  
  - IR lead satisfaction ≥ 4.7/5.  
  - Evidence SLA compliance ≥ 99%.  
  - ATT&CK coverage completeness +30pp per quarter.  

- **Engineering SLOs**:  
  - Artifact ingest & hash < 15s p95.  
  - Timeline correlation < 45s p95 for 10k events.  
  - Draft report generation < 90s p95.  
  - Export < 10s p95 with < 1% failure rate.  
