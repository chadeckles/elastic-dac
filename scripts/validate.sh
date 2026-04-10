#!/usr/bin/env bash
# =============================================================================
# validate.sh — Quick validation of the running lab
# =============================================================================
# Checks:
#   1. Elasticsearch cluster health
#   2. Kibana status
#   3. Detection rules count
#   4. Exception lists count
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source env
if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"
ES_URL="http://localhost:9200"
KB_URL="http://localhost:5601"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }

echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Detection-as-Code Lab — Validation                 ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

# ----- Elasticsearch Health ---------------------------------------------------
echo -e "${CYAN}Elasticsearch${NC}"
ES_HEALTH=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" 2>/dev/null)
if echo "$ES_HEALTH" | grep -qE '"status":"(green|yellow)"'; then
  STATUS=$(echo "$ES_HEALTH" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
  pass "Cluster health: ${STATUS}"
else
  fail "Elasticsearch is not reachable"
fi

# ----- Kibana Status ----------------------------------------------------------
echo -e "${CYAN}Kibana${NC}"
KB_STATUS=$(curl -s "${KB_URL}/api/status" 2>/dev/null)
if echo "$KB_STATUS" | grep -q '"overall":{"level":"available"'; then
  pass "Kibana is available"
else
  fail "Kibana is not reachable"
fi

# ----- Detection Rules --------------------------------------------------------
echo -e "${CYAN}Detection Rules${NC}"
RULES_RESPONSE=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  -X POST "${KB_URL}/api/detection_engine/rules/_find" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{"per_page": 1}' 2>/dev/null)
RULES_TOTAL=$(echo "$RULES_RESPONSE" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2)
if [[ -n "$RULES_TOTAL" ]]; then
  pass "Total detection rules: ${RULES_TOTAL}"
else
  fail "Could not query detection rules"
fi

# ----- Exception Lists --------------------------------------------------------
echo -e "${CYAN}Exception Lists${NC}"
EXCEPTIONS_RESPONSE=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  -X GET "${KB_URL}/api/exception_lists/_find?per_page=1" \
  -H 'kbn-xsrf: true' 2>/dev/null)
EXCEPTIONS_TOTAL=$(echo "$EXCEPTIONS_RESPONSE" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2)
if [[ -n "$EXCEPTIONS_TOTAL" ]]; then
  pass "Total exception lists: ${EXCEPTIONS_TOTAL}"
else
  fail "Could not query exception lists"
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Validation complete${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
