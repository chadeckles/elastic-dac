# =============================================================================
# Makefile — Detection as Code (Elastic Stack)
# =============================================================================
# Shortcuts for common development and deployment tasks against a LIVE
# Elasticsearch / Kibana cluster. Authentication is API-key based and read
# from the environment.
#
# Required env vars for any target that talks to the cluster
# (`plan`, `apply`, `destroy`, `import-rule`, `list-rules`, `dac-*`):
#
#   ELASTICSEARCH_ENDPOINTS   https://<deployment>.es.<region>.aws.elastic-cloud.com:9243
#   ELASTICSEARCH_API_KEY     <encoded API key>
#   KIBANA_ENDPOINT           https://<deployment>.kb.<region>.aws.elastic-cloud.com:9243
#   KIBANA_API_KEY            <same encoded API key, typically>
#
# Usage:
#   make help          — Show all available targets
#   make creds-check   — Verify env vars + reach the cluster
#   make plan          — terraform plan
#   make apply         — terraform apply
#   make test          — pytest rule unit tests
# =============================================================================

.DEFAULT_GOAL := help

SHELL         := /bin/bash
TF_DIR        := terraform
TESTS_DIR     := tests
SCRIPTS_DIR   := scripts

# ---------------------------------------------------------------------------
# Cluster connectivity check
# ---------------------------------------------------------------------------
.PHONY: creds-check
creds-check: ## 🔌 Verify env vars are set and the live Kibana is reachable
	@if [[ -z "$$KIBANA_ENDPOINT" ]]; then echo "✗ KIBANA_ENDPOINT not set"; exit 1; fi
	@if [[ -z "$$KIBANA_API_KEY"  ]]; then echo "✗ KIBANA_API_KEY not set";  exit 1; fi
	@echo "→ Pinging Kibana at $$KIBANA_ENDPOINT …"
	@curl --silent --show-error --fail \
		-H "Authorization: ApiKey $$KIBANA_API_KEY" \
		-H 'kbn-xsrf: true' \
		"$$KIBANA_ENDPOINT/api/status" \
		| python3 -c "import sys,json; d=json.load(sys.stdin); print('  ✓ Kibana', d.get('version',{}).get('number','?'), 'available')"

# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------
.PHONY: init
init: ## Run terraform init
	cd $(TF_DIR) && terraform init -input=false

.PHONY: fmt
fmt: ## Run terraform fmt (recursive)
	cd $(TF_DIR) && terraform fmt -recursive

.PHONY: validate
validate: ## Run terraform validate
	cd $(TF_DIR) && terraform validate

.PHONY: plan
plan: ## Run terraform plan
	cd $(TF_DIR) && terraform init -input=false >/dev/null 2>&1 && terraform plan -input=false

.PHONY: apply
apply: ## Run terraform apply (auto-approve)
	cd $(TF_DIR) && terraform init -input=false >/dev/null 2>&1 && terraform apply -auto-approve -input=false

.PHONY: destroy
destroy: ## Run terraform destroy (auto-approve)  ⚠️ destructive against the live cluster
	cd $(TF_DIR) && terraform destroy -auto-approve -input=false

.PHONY: output
output: ## Show terraform outputs
	cd $(TF_DIR) && terraform output

# ---------------------------------------------------------------------------
# Rule & Exception Wizards
# ---------------------------------------------------------------------------
.PHONY: new-rule
new-rule: ## 🧙 Interactive wizard to create a new detection rule
	@chmod +x $(SCRIPTS_DIR)/new_rule.sh
	@$(SCRIPTS_DIR)/new_rule.sh

.PHONY: new-exception
new-exception: ## 🧙 Interactive wizard to create a new exception list
	@chmod +x $(SCRIPTS_DIR)/new_exception.sh
	@$(SCRIPTS_DIR)/new_exception.sh

# ---------------------------------------------------------------------------
# Import from Kibana GUI
# ---------------------------------------------------------------------------
.PHONY: list-rules
list-rules: ## 📋 List all detection rules currently in the live Kibana
	@python3 $(SCRIPTS_DIR)/import_gui_rule.py --list

.PHONY: import-rule
import-rule: ## 📥 Import a GUI-created rule into Terraform (by name)
	@python3 $(SCRIPTS_DIR)/import_gui_rule.py --name "$(NAME)"

.PHONY: cheatsheet
cheatsheet: ## 📋 Print a quick-reference cheatsheet to the terminal
	@echo ""
	@echo "  ╔═══════════════════════════════════════════════════════════════╗"
	@echo "  ║         Detection as Code — Quick Reference                  ║"
	@echo "  ╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  ┌─────────────────────────────────────────────────────────────┐"
	@echo "  │  ENVIRONMENT (live cluster)                                │"
	@echo "  │    export KIBANA_ENDPOINT=https://...:9243                 │"
	@echo "  │    export KIBANA_API_KEY=<encoded>                         │"
	@echo "  │    make creds-check     Verify cluster reachable           │"
	@echo "  ├─────────────────────────────────────────────────────────────┤"
	@echo "  │  CREATE                                                    │"
	@echo "  │    make new-rule         Create a new detection rule       │"
	@echo "  │    make new-exception    Create a new exception list       │"
	@echo "  ├─────────────────────────────────────────────────────────────┤"
	@echo "  │  IMPORT FROM KIBANA                                        │"
	@echo "  │    make list-rules       List all rules in Kibana          │"
	@echo "  │    make import-rule      Import a single GUI rule into TF  │"
	@echo "  ├─────────────────────────────────────────────────────────────┤"
	@echo "  │  TEST & DEPLOY                                             │"
	@echo "  │    make test             Validate all rules (run first!)   │"
	@echo "  │    make plan             Preview what Terraform will do    │"
	@echo "  │    make apply            Deploy rules to Elastic Security  │"
	@echo "  ├─────────────────────────────────────────────────────────────┤"
	@echo "  │  WORKFLOW                                                  │"
	@echo "  │    1. make new-rule      (answer prompts)                  │"
	@echo "  │    2. make test          (must pass before push)           │"
	@echo "  │    3. git add + commit + push                              │"
	@echo "  │    4. Open MR → CI runs tests + plan → review → merge     │"
	@echo "  │    5. Merge → CI applies to Elastic Security               │"
	@echo "  └─────────────────────────────────────────────────────────────┘"
	@echo ""

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run pytest rule unit tests
	python3 -m pip install -q -r $(TESTS_DIR)/requirements.txt
	python3 -m pytest

.PHONY: test-verbose
test-verbose: ## Run pytest with full output
	python3 -m pip install -q -r $(TESTS_DIR)/requirements.txt
	python3 -m pytest -v --tb=long

# ---------------------------------------------------------------------------
# Upstream Sync
# ---------------------------------------------------------------------------
.PHONY: sync-upstream
sync-upstream: ## Sync from elastic/detection-rules and update changelog
	python3 $(SCRIPTS_DIR)/sync_upstream_rules.py

.PHONY: sync-upstream-dry
sync-upstream-dry: ## Dry-run sync (generates changelog, doesn't update tracking)
	python3 $(SCRIPTS_DIR)/sync_upstream_rules.py --dry-run

.PHONY: sync-upstream-full
sync-upstream-full: ## First-time sync cataloging all upstream rules
	python3 $(SCRIPTS_DIR)/sync_upstream_rules.py --first-sync-full

# ---------------------------------------------------------------------------
# Detection-rules CLI (optional — requires detection-rules installed)
# ---------------------------------------------------------------------------
.PHONY: dac-export
dac-export: ## Export custom rules from Kibana via detection-rules CLI
	@chmod +x $(SCRIPTS_DIR)/dac-sync.sh
	$(SCRIPTS_DIR)/dac-sync.sh export

.PHONY: dac-import
dac-import: ## Import rules to Kibana via detection-rules CLI
	@chmod +x $(SCRIPTS_DIR)/dac-sync.sh
	$(SCRIPTS_DIR)/dac-sync.sh import

.PHONY: dac-setup
dac-setup: ## Initialise custom rules directory for detection-rules CLI
	@chmod +x $(SCRIPTS_DIR)/dac-sync.sh
	$(SCRIPTS_DIR)/dac-sync.sh setup-custom

# ---------------------------------------------------------------------------
# CI shortcut
# ---------------------------------------------------------------------------
.PHONY: ci
ci: fmt validate test plan ## Run full CI pipeline locally: fmt → validate → test → plan

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "Detection as Code — Make targets"
	@echo "================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
