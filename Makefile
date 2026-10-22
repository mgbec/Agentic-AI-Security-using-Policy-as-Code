# Policy-as-code task runner for the OWASP Agentic AI (ASI) repo.
# On Windows without `make`, use ./tasks.ps1 with the same target names.

SHELL := /bin/bash
TF_DIR := terraform

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install tools (Python) + print binary install links
	pip install -r requirements.txt
	pre-commit install
	@echo ""
	@echo "Install these binaries via your package manager if missing:"
	@echo "  terraform -> https://developer.hashicorp.com/terraform/install"
	@echo "  conftest  -> https://www.conftest.dev/install/"
	@echo "  gitleaks  -> https://github.com/gitleaks/gitleaks#installing"

.PHONY: all
all: schema opa semgrep checkov tf ## Run every check

.PHONY: schema
schema: ## Validate agent manifests against JSON Schemas (ASI01/02/04/06/07)
	check-jsonschema --schemafile schemas/agent.schema.json agents/*.agent.yaml
	check-jsonschema --schemafile schemas/tools.schema.json agents/tools/*.yaml
	check-jsonschema --schemafile schemas/mcp.schema.json agents/mcp/*.json

.PHONY: opa
opa: ## Conftest on agent configs + supply chain (ASI01/02/04/06/07/09/10)
	conftest test agents/*.agent.yaml --policy policies/opa --namespace agent
	conftest test agents/tools/*.yaml --policy policies/opa --namespace supplychain
	conftest test agents/mcp/*.json --policy policies/opa --namespace supplychain

.PHONY: semgrep
semgrep: ## Agent-code SAST (ASI05 RCE, ASI06 memory, ASI02 loops)
	semgrep scan --config policies/semgrep/agentic.yaml --error src

.PHONY: checkov
checkov: ## Terraform scan + custom ASI policies (ASI03)
	checkov -d $(TF_DIR) --external-checks-dir policies/checkov --compact

.PHONY: tf
tf: ## Terraform fmt/validate + Conftest on the plan (ASI03/08/10)
	terraform -chdir=$(TF_DIR) fmt -check -recursive
	terraform -chdir=$(TF_DIR) init -backend=false -input=false
	terraform -chdir=$(TF_DIR) validate
	terraform -chdir=$(TF_DIR) plan -out=tfplan.binary -input=false
	terraform -chdir=$(TF_DIR) show -json tfplan.binary > $(TF_DIR)/tfplan.json
	conftest test $(TF_DIR)/tfplan.json --policy policies/opa --namespace tfplan

.PHONY: clean
clean: ## Remove Terraform working files
	rm -rf $(TF_DIR)/.terraform $(TF_DIR)/.terraform.lock.hcl
	rm -f $(TF_DIR)/tfplan.binary $(TF_DIR)/tfplan.json
