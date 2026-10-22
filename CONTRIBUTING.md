# Contributing

This repo enforces the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) (ASI01–ASI10)
via policy as code. Changes to agent configs, tool/MCP manifests, agent code,
or Terraform must pass every policy gate before merge.

## Local workflow

```bash
make install          # or: ./tasks.ps1 install  (elevated PowerShell on Windows)
make all              # or: ./tasks.ps1 all
```

`make all` runs schema validation, OPA/Conftest (agent configs + supply
chain), Semgrep, Checkov, and the Terraform plan policy. Fix findings before
opening a PR. Pre-commit hooks run the fast subset on `git commit`.

## Required status checks (repo admins)

CI runs on every PR but only *blocks* merges once branch protection is set:

1. **Settings → Branches → Add branch protection rule**, pattern `main`.
2. Enable **Require a pull request before merging**.
3. Enable **Require status checks to pass before merging** and select:
   - `gitleaks (secrets)`
   - `schema (agent manifests)`
   - `conftest (agent configs)`
   - `semgrep (agent code)`
   - `checkov + conftest (infra)`
4. Save. (Check names appear only after the workflow has run once.)

## Where each control lives

| Scope | Where | ASI coverage |
|-------|-------|--------------|
| Agent config shape | `schemas/agent.schema.json` | ASI01/02/06/07/09/10 |
| Tool / MCP manifest shape | `schemas/tools.schema.json`, `schemas/mcp.schema.json` | ASI02/04/07 |
| Agent config logic | `policies/opa/agent_config.rego` | ASI01/02/06/07/09/10 |
| Supply-chain pinning | `policies/opa/supply_chain.rego` | ASI04/02/07 |
| Agent code sinks | `policies/semgrep/agentic.yaml` | ASI05/06/02 |
| Agent identity (IAM) | `policies/checkov/asi03_agent_identity.py` | ASI03 |
| Infra plan graph | `policies/opa/terraform_plan.rego` | ASI03/08/10 |

When adding a rule, tag it with the specific ASI code in a comment and update
the coverage table in `README.md`.

## What policy as code can and cannot do here

These gates catch *declarable* risks in config and code before deploy. The
behavioral risks — ASI08 Cascading Failures, ASI09 Human-Agent Trust, ASI10
Rogue Agents after drift — are mitigated at runtime (least agency, signed
inter-agent messages, human approval for high-impact actions, fast
revocation). Policy as code enforces the *preconditions* for those controls
(e.g. a kill-switch target must exist, high-impact actions must be flagged
for approval), but does not replace runtime guardrails, agent observability,
red-teaming, and human oversight.
