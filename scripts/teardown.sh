#!/usr/bin/env bash
# =============================================================================
# teardown.sh — Tear down the local Detection-as-Code lab
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TF_DIR="${ROOT_DIR}/terraform"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }

# ----- Terraform Destroy (optional) ------------------------------------------
if [[ -f "${TF_DIR}/.terraform/terraform.tfstate" ]] || [[ -f "${TF_DIR}/terraform.tfstate" ]]; then
  info "Running terraform destroy …"
  cd "${TF_DIR}"
  terraform destroy -auto-approve -input=false 2>/dev/null || true
  ok "Terraform resources destroyed."
fi

# ----- Docker Compose Down ----------------------------------------------------
info "Stopping Docker Compose stack and removing volumes …"
docker compose -f "${ROOT_DIR}/docker-compose.yml" down -v
ok "Docker stack removed."

echo -e "${GREEN}Lab environment torn down.${NC}"
