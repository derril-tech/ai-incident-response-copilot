Great — here’s a **`.cursor/rules/README.md`** you can drop in to give yourself (and Cursor/Claude) a quick orientation on what each rules file is about and when it applies.

---

# Cursor Rules — README

This folder defines the **governing rules** for how code, docs, and tasks are scaffolded and evolved across all SaaS projects.
Every `.mdc` file here is **enforced context** for Cursor/Claude coding sessions.

---

## Rule Files Overview

### 00-always-persistence.mdc

* **Purpose:** Session continuity & mandatory doc updates.
* Ensures every code or doc change is mirrored in `/PLAN.md`, `/TODO.md`, and `/ARCH.md`.
* Golden rule: no silent drift between code and docs.

---

### 10-ai-integration-foundation.mdc

* **Purpose:** Framework-agnostic foundation for AI, automation, background jobs, and integrations.
* Covers schemas/contracts, adapters, orchestration, optional AI prompts, observability, and DX rules.
* **Modes:**

  * Mode A — No orchestration/AI (pure CRUD SaaS)
  * Mode B — Light automation (jobs, APIs, webhooks)
  * Mode C — Full orchestration/AI (workflows, prompts, queues)
* Projects declare their mode in `/PLAN.md` + `/ARCH.md`.

---

### 20-auto-python.mdc

* **Purpose:** Python quality, packaging, typing.
* Enforce: Pydantic/FastAPI patterns, black/isort, mypy typing, pytest fixtures.
* Cursor generates: structured code, docstrings, tests.

---

### 21-auto-js-ts.mdc

* **Purpose:** TypeScript/Node build & conventions.
* Enforce: strict types, ESLint + Prettier, Zod schemas, OpenAPI client codegen.
* Cursor generates: typed clients, React hooks, API SDKs.

---

### 30-testing.mdc

* **Purpose:** Testing strategy across all stacks.
* Unit tests for pure logic; contract tests for APIs/adapters; integration/E2E with golden paths.
* CI must run `lint → typecheck → test → build`.

---

### 40-security-and-secrets.mdc

* **Purpose:** Repo hygiene & security practices.
* No raw secrets committed.
* All secrets must come via env or cloud secrets manager reference.
* Enforces audit log redaction, PII masking, and RBAC checks.

---

### 50-commits-and-docs.mdc

* **Purpose:** Conventional commits & doc upkeep.
* Commit format: `feat|fix|chore|docs|test(scope): message`.
* PRs must update `/PLAN.md`, `/TODO.md`, `/ARCH.md` where relevant.
* Cursor must assist in generating commit messages and updating docs.

---

## How to Use These Rules

1. **Always start** from `/PLAN.md` → *Current Goal* and *Next 3 Tasks*.
2. Cursor coding sessions must load the relevant `.mdc` rule(s).
3. Any new integration, background job, or AI layer must follow `10-ai-integration-foundation.mdc`.
4. Always cross-check changes against this ruleset before merge.

---


