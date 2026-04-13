#!/usr/bin/env bash
# =============================================================================
# setup.sh — Bootstrap the local Detection-as-Code lab
# =============================================================================
# This script:
#   1. Copies .env.example → .env (if not present)
#   2. Starts the Docker ELK stack
#   3. Waits for Elasticsearch & Kibana to become healthy
#   4. Sets the kibana_system password (required for Kibana → ES auth)
#   5. Initialises Terraform
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
TF_DIR="${ROOT_DIR}/terraform"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ----- 1. Environment file ---------------------------------------------------
if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  info "Creating .env from .env.example …"
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  ok ".env created — review and adjust if needed."
else
  ok ".env already exists."
fi

# Source the env file for variable access
set -a
# shellcheck disable=SC1091
source "${ROOT_DIR}/.env"
set +a

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"

# ----- 2. Start Docker Compose -----------------------------------------------
info "Starting Docker Compose stack …"
docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d

# ----- 3. Wait for Elasticsearch ----------------------------------------------
info "Waiting for Elasticsearch to be ready …"
until curl -s -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200/_cluster/health 2>/dev/null | grep -qE '"status":"(green|yellow)"'; do
  sleep 5
  printf '.'
done
echo ""
ok "Elasticsearch is ready."

# ----- 4. Set kibana_system password -----------------------------------------
info "Setting kibana_system user password …"
curl -s -X POST "http://localhost:9200/_security/user/kibana_system/_password" \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -d "{\"password\": \"${ELASTIC_PASSWORD}\"}" > /dev/null 2>&1
ok "kibana_system password configured."

# ----- 5. Wait for Kibana ----------------------------------------------------
info "Waiting for Kibana to be ready (this may take 1-2 minutes) …"
until curl -s http://localhost:5601/api/status 2>/dev/null | grep -q '"overall":{"level":"available"'; do
  sleep 5
  printf '.'
done
echo ""
ok "Kibana is ready at http://localhost:5601"

# ----- 6. Copy terraform.tfvars ----------------------------------------------
if [[ ! -f "${TF_DIR}/terraform.tfvars" ]]; then
  info "Creating terraform.tfvars from example …"
  cp "${TF_DIR}/terraform.tfvars.example" "${TF_DIR}/terraform.tfvars"
  ok "terraform.tfvars created."
fi

# ----- 7. Terraform Init -----------------------------------------------------
info "Running terraform init …"
cd "${TF_DIR}"
terraform init -input=false
ok "Terraform initialised."

# ----- 8. Terraform Apply (with retry for prebuilt rules provider quirk) ------
# The elasticstack provider reports an error on the FIRST apply when prebuilt
# rules are installed (plans 0, gets 1419). The rules DO install — the state
# just needs a second apply to reconcile. This only happens on a fresh instance.
info "Deploying baseline rules and exceptions …"
if ! terraform apply -auto-approve -input=false 2>&1 | tee /dev/stderr | grep -q 'Apply complete'; then
  warn "First apply hit the prebuilt-rules provider quirk — retrying …"
  terraform apply -auto-approve -input=false
fi
ok "Baseline deployed."

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Detection-as-Code lab is ready!                        ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║   Elasticsearch : http://localhost:9200                    ║${NC}"
echo -e "${GREEN}║   Kibana        : http://localhost:5601                    ║${NC}"
echo -e "${GREEN}║   Username      : elastic                                 ║${NC}"
echo -e "${GREEN}║   Password      : ${ELASTIC_PASSWORD}                              ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║   Rules, exceptions, and prebuilt rules are deployed.     ║${NC}"
echo -e "${GREEN}║   Open Kibana → Security → Rules to verify.               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
