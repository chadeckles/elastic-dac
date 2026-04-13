#!/usr/bin/env bash
# =============================================================================
# demo_cleanup.sh — Reset the environment between demo runs
# =============================================================================
# Reverts all file changes, destroys Terraform-managed resources, wipes
# GUI-created rules from Kibana, and redeploys the baseline state.
#
# Usage:
#   make demo-reset          (recommended)
#   bash scripts/demo_cleanup.sh
#
# What it does:
#   1. Reverts terraform/ and DEMO_RUNBOOK.md to the last committed state
#   2. Removes any demo git branches
#   3. Runs terraform destroy to clean Elastic
#   4. Deletes any GUI-created (non-Terraform) custom rules from Kibana
#   5. Re-initialises and re-applies the baseline rules + exceptions
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TF_DIR="${ROOT_DIR}/terraform"

# Source env
if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a; source "${ROOT_DIR}/.env"; set +a
fi

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"
KB_URL="${KIBANA_ENDPOINT:-http://localhost:5601}"
KB_USER="${KIBANA_USERNAME:-elastic}"
KB_PASS="${KIBANA_PASSWORD:-changeme}"

# Colours
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}  ✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Detection as Code — Demo Environment Reset${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ---- Confirm ----------------------------------------------------------------
echo -e "${YELLOW}This will:${NC}"
echo "  • Revert all uncommitted file changes in terraform/"
echo "  • Delete demo git branches (demo/*)"
echo "  • Terraform destroy all managed resources"
echo "  • Delete GUI-created custom rules from Kibana"
echo "  • Redeploy baseline rules and exceptions"
echo ""
read -p "Continue? (y/N): " confirm
[[ "$confirm" =~ ^[Yy] ]] || { echo "Aborted."; exit 0; }
echo ""

# ---- Step 1: Revert file changes -------------------------------------------
info "Reverting file changes to last commit…"

cd "$ROOT_DIR"

# Restore tracked files
git checkout HEAD -- terraform/ 2>/dev/null && ok "Restored terraform/ to HEAD" || warn "No changes to revert in terraform/"

# Remove untracked files in custom_rules/ and exceptions/ (demo artifacts)
untracked_rules=$(git clean -n terraform/custom_rules/ terraform/exceptions/ 2>/dev/null | wc -l | tr -d ' ')
if [[ "$untracked_rules" -gt 0 ]]; then
  git clean -f terraform/custom_rules/ terraform/exceptions/
  ok "Removed ${untracked_rules} untracked demo file(s)"
else
  ok "No untracked demo files to clean"
fi

# ---- Step 2: Clean up demo git branches ------------------------------------
info "Cleaning up demo git branches…"

# Switch to main first if on a demo branch
current_branch=$(git branch --show-current)
if [[ "$current_branch" != "main" ]]; then
  git checkout main 2>/dev/null
  ok "Switched back to main"
fi

# Delete local demo branches
demo_branches=$(git branch --list 'demo/*' 2>/dev/null | tr -d ' *')
if [[ -n "$demo_branches" ]]; then
  echo "$demo_branches" | while read -r branch; do
    git branch -D "$branch" 2>/dev/null
    ok "Deleted branch: $branch"
  done
else
  ok "No demo branches to clean"
fi

# ---- Step 3: Terraform destroy ----------------------------------------------
info "Destroying Terraform-managed resources in Elastic…"

cd "$TF_DIR"
terraform init -input=false -no-color >/dev/null 2>&1
terraform destroy -auto-approve -input=false -no-color 2>&1 | tail -5
ok "Terraform destroy complete"

# ---- Step 4: Delete GUI-created rules from Kibana ---------------------------
info "Cleaning up GUI-created rules from Kibana…"

# Fetch all custom (mutable) rules
rules_json=$(curl -s -u "${KB_USER}:${KB_PASS}" \
  "${KB_URL}/api/detection_engine/rules/_find?per_page=100&sort_field=name" \
  -H 'kbn-xsrf: true' 2>/dev/null || echo '{"data":[]}')

# Extract rule IDs for non-immutable (custom) rules
rule_ids=$(echo "$rules_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin).get('data', [])
    for r in data:
        if not r.get('immutable', False):
            print(r.get('id', ''))
except: pass
" 2>/dev/null)

deleted=0
if [[ -n "$rule_ids" ]]; then
  while IFS= read -r rid; do
    [[ -z "$rid" ]] && continue
    curl -s -u "${KB_USER}:${KB_PASS}" \
      -X DELETE "${KB_URL}/api/detection_engine/rules?id=${rid}" \
      -H 'kbn-xsrf: true' >/dev/null 2>&1
    deleted=$((deleted + 1))
  done <<< "$rule_ids"
fi
ok "Deleted ${deleted} GUI-created rule(s) from Kibana"

# Also clean up any leftover exception lists
exc_json=$(curl -s -u "${KB_USER}:${KB_PASS}" \
  "${KB_URL}/api/exception_lists/_find?per_page=100" \
  -H 'kbn-xsrf: true' 2>/dev/null || echo '{"data":[]}')

exc_deleted=0
exc_ids=$(echo "$exc_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin).get('data', [])
    for e in data:
        if e.get('type') == 'detection':
            print(e.get('id', ''))
except: pass
" 2>/dev/null)

if [[ -n "$exc_ids" ]]; then
  while IFS= read -r eid; do
    [[ -z "$eid" ]] && continue
    curl -s -u "${KB_USER}:${KB_PASS}" \
      -X DELETE "${KB_URL}/api/exception_lists?id=${eid}" \
      -H 'kbn-xsrf: true' >/dev/null 2>&1
    exc_deleted=$((exc_deleted + 1))
  done <<< "$exc_ids"
fi
ok "Deleted ${exc_deleted} leftover exception list(s) from Kibana"

# ---- Step 5: Redeploy baseline ----------------------------------------------
info "Redeploying baseline rules and exceptions…"

terraform init -input=false -no-color >/dev/null 2>&1
terraform apply -auto-approve -input=false -no-color 2>&1 | tail -5
ok "Baseline deployed"

# ---- Step 6: Quick health check ---------------------------------------------
info "Verifying environment…"

# Elasticsearch
if curl -s -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200/_cluster/health 2>/dev/null | grep -qE '"status":"(green|yellow)"'; then
  ok "Elasticsearch is healthy"
else
  warn "Elasticsearch health check failed — is Docker running?"
fi

# Kibana
if curl -s "${KB_URL}/api/status" 2>/dev/null | grep -q '"overall":{"level":"available"'; then
  ok "Kibana is available"
else
  warn "Kibana health check failed"
fi

# Rule count
rule_count=$(curl -s -u "${KB_USER}:${KB_PASS}" \
  "${KB_URL}/api/detection_engine/rules/_find?per_page=1" \
  -H 'kbn-xsrf: true' 2>/dev/null | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('total', '?'))
except: print('?')
" 2>/dev/null)
ok "Detection rules in Kibana: ${rule_count}"

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Environment reset complete — ready for next demo run${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
