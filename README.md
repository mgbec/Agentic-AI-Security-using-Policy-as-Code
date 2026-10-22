# OWASP Agentic AI Security — Policy as Code (Terraform + GitHub)

Policy-as-code scaffolding that catches the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) (the
"Agentic AI Top 10", codes **ASI01–ASI10**, published by the OWASP GenAI
Security Project, Dec 2025) **before an agent ships** — first at the
developer's machine via pre-commit hooks, then as an authoritative gate in
GitHub Actions.

Target stack: **Terraform** (AWS) + **GitHub**.

> OWASP category names are used as factual taxonomy labels. Descriptions here
> are independently authored / paraphrased for licensing compliance.

---

## Why this project is different from the API Security one

The [OWASP API Security Top 10](https://owasp.org/API-Security/) is almost
entirely about infrastructure and the HTTP contract, so IaC scanning covers
most of it. **Agentic risks live somewhere else**: in the agent's
*configuration* — its tools, MCP servers, skills, prompts, memory stores,
and the credentials and autonomy it's granted. An agent that plans, calls
tools, and acts with delegated authority can do damage no firewall rule sees.

So this project shifts the primary scan targets from Terraform to the
**agent manifests and configs** (plus supporting infra guardrails):

| Scan target | Lives in | Catches |
|-------------|----------|---------|
| Agent config / autonomy | `agents/*.yaml` | ASI01, ASI02, ASI09, ASI10 |
| Tool / skill manifests | `agents/tools/*.yaml` | ASI02, ASI04, ASI05 |
| MCP server definitions | `agents/mcp/*.json` | ASI04, ASI07 |
| Agent handler code | `src/` | ASI05, ASI06 |
| Infra (IAM, logging, secrets) | `terraform/` | ASI03, ASI08, ASI10 |

OWASP's running advice across all ten: **grant the least autonomy the task
needs, and make observability mandatory** — you can't put a kill switch on an
agent you don't know exists.

---

## What's in here

```
.
├── .pre-commit-config.yaml       # local fast-feedback hooks
├── .github/workflows/
│   └── policy-as-code.yml         # CI enforcement gate (PR check)
├── agents/
│   ├── summarizer.agent.yaml      # example agent config (passes policy)
│   ├── tools/
│   │   └── tools.yaml             # tool/skill manifest w/ scopes + approval
│   ├── mcp/
│   │   └── mcp.json               # MCP server definitions (pinned, allowlisted)
│   └── prompts/
│       └── system.md              # system prompt (injection-resistant)
├── schemas/
│   ├── agent.schema.json          # JSON Schema for agent configs
│   ├── tools.schema.json          # JSON Schema for tool manifests
│   └── mcp.schema.json            # JSON Schema for MCP configs
├── policies/
│   ├── opa/
│   │   ├── agent_config.rego       # ASI01/02/03/09/10 on agent configs
│   │   ├── supply_chain.rego       # ASI04 on tools + MCP (pinning/allowlist)
│   │   └── terraform_plan.rego     # ASI03/08/10 on the Terraform plan
│   ├── checkov/
│   │   └── asi03_agent_identity.py # scoped/short-lived agent credentials
│   └── semgrep/
│       └── agentic.yaml            # ASI05 RCE, ASI06 memory poisoning
├── src/
│   └── agent_handler.py            # example agent loop (SAST target)
├── terraform/
│   ├── main.tf                     # scoped IAM + logging + kill-switch infra
│   └── variables.tf
├── Makefile / tasks.ps1            # task runners
├── requirements.txt                # pinned Python tools
└── CONTRIBUTING.md
```

---

## ASI01–ASI10 → where it's caught

| Risk | What it is (short) | Caught by |
|------|--------------------|-----------|
| **ASI01** Agent Goal Hijack | injected instructions redirect the plan | Spectral/schema (prompt + untrusted-input flags), OPA (input trust boundaries) |
| **ASI02** Tool Misuse & Exploitation | allowed tool pointed at the wrong target | OPA (tool scopes + per-tool approval), Semgrep (unbounded tool loops) |
| **ASI03** Identity & Privilege Abuse | over-broad / long-lived delegated creds | Checkov `CKV_ASI03_*`, OPA plan (scoped role, short TTL) |
| **ASI04** Agentic Supply Chain | unpinned/untrusted tools, MCP, skills | OPA `supply_chain.rego` (pinning + allowlist), schema |
| **ASI05** Unexpected Code Execution | eval / shell / pickle on model output | Semgrep `agentic.yaml` (RCE sinks) |
| **ASI06** Memory & Context Poisoning | unsanitized data into memory / RAG | Semgrep (unsanitized memory writes), OPA (RAG source allowlist) |
| **ASI07** Insecure Inter-Agent Comms | unauthenticated / unvalidated messages | Schema + OPA (auth required on agent endpoints) |
| **ASI08** Cascading Failures | one fault fans out across agents | OPA (concurrency/rate caps), Terraform (isolation) |
| **ASI09** Human-Agent Trust | confident output steers risky approval | OPA (high-impact actions require human approval) |
| **ASI10** Rogue Agents | agent drifts beyond scope, keeps acting | OPA (inventory tags + kill-switch required), Terraform |

The first few leave evidence in config and code — block them pre-deploy. The
rest are runtime behaviors you mitigate by design: least agency, signed
inter-agent messages, human approval for high-impact actions, and a fast
revocation / kill switch. Policy as code enforces the *design preconditions*
for those runtime controls (e.g. "a kill-switch target must exist").

---

## Quick start

```bash
make install            # or: ./tasks.ps1 install  (elevated PowerShell on Windows)
make all                # run every check
```

Individual checks: `make schema`, `make opa`, `make semgrep`, `make checkov`,
`make tf`. See [CONTRIBUTING.md](CONTRIBUTING.md) for required-checks setup.

---

## Notes & caveats

- This is a **young standard** (first edition). Treat these policies as a
  starting baseline and tune them to your agent framework.
- Policy as code catches *declarable* risks in config and code. It complements
  but does not replace runtime guardrails, agent observability, red-teaming,
  and human oversight — especially for ASI08/09/10, which are behavioral.
- The example `agents/` and `terraform/` are built to **pass**; flip a value
  (e.g. remove a tool scope, unpin an MCP server) to watch a gate fail.
