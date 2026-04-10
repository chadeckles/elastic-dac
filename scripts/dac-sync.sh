#!/usr/bin/env bash
# =============================================================================
# dac-sync.sh — Detection-rules CLI integration
# =============================================================================
# Complements the Terraform-based DaC workflow by providing import/export
# functionality via Elastic's detection-rules CLI.
#
# This script requires the detection-rules Python package:
#   git clone https://github.com/elastic/detection-rules.git
#   cd detection-rules && pip install .[dev]
#
# Usage:
#   ./scripts/dac-sync.sh export [--space <space>]  # Export rules from Kibana
#   ./scripts/dac-sync.sh import [--space <space>]  # Import rules to Kibana
#   ./scripts/dac-sync.sh setup-custom               # Set up custom rules dir
#
# Reference:
#   https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features
#   https://dac-reference.readthedocs.io/en/latest/
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CUSTOM_RULES_DIR="${ROOT_DIR}/detection-rules-export"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Source env for Kibana credentials
if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

KIBANA_URL="${KIBANA_ENDPOINT:-http://localhost:5601}"
KIBANA_USER="${KIBANA_USERNAME:-elastic}"
KIBANA_PASS="${KIBANA_PASSWORD:-changeme}"

# Verify detection-rules is installed
check_dr_installed() {
  if ! python -m detection_rules --help >/dev/null 2>&1; then
    err "detection-rules CLI not found."
    echo ""
    echo "Install it with:"
    echo "  git clone https://github.com/elastic/detection-rules.git"
    echo "  cd detection-rules && pip install .[dev]"
    echo ""
    echo "Or use the Terraform-only workflow: make plan && make apply"
    exit 1
  fi
}

# ---- Export rules from Kibana ------------------------------------------------
cmd_export() {
  local space="${1:-default}"
  check_dr_installed

  mkdir -p "${CUSTOM_RULES_DIR}/rules"

  info "Exporting custom rules from Kibana (space: ${space}) …"
  python -m detection_rules kibana \
    --kibana-url "${KIBANA_URL}" \
    --kibana-user "${KIBANA_USER}" \
    --kibana-password "${KIBANA_PASS}" \
    --space "${space}" \
    export-rules \
    -d "${CUSTOM_RULES_DIR}/rules/" \
    -sv \
    -cro \
    -e \
    -ac

  ok "Rules exported to ${CUSTOM_RULES_DIR}/rules/"
  echo ""
  echo "Exported rules can be reviewed, committed, and then deployed via:"
  echo "  terraform plan / terraform apply"
}

# ---- Import rules to Kibana --------------------------------------------------
cmd_import() {
  local space="${1:-default}"
  check_dr_installed

  if [[ ! -d "${CUSTOM_RULES_DIR}/rules" ]]; then
    err "No rules found at ${CUSTOM_RULES_DIR}/rules — run 'export' first."
    exit 1
  fi

  info "Importing rules to Kibana (space: ${space}) …"
  python -m detection_rules kibana \
    --kibana-url "${KIBANA_URL}" \
    --kibana-user "${KIBANA_USER}" \
    --kibana-password "${KIBANA_PASS}" \
    --space "${space}" \
    import-rules \
    -d "${CUSTOM_RULES_DIR}/rules/" \
    --overwrite \
    -e \
    -ac

  ok "Rules imported to Kibana space '${space}'."
}

# ---- Setup custom rules directory --------------------------------------------
cmd_setup_custom() {
  check_dr_installed

  info "Setting up custom rules directory at ${CUSTOM_RULES_DIR} …"
  python -m detection_rules custom-rules setup-config "${CUSTOM_RULES_DIR}"
  ok "Custom rules directory initialised."
  echo ""
  echo "Directory structure:"
  find "${CUSTOM_RULES_DIR}" -type f | head -20
}

# ---- Usage -------------------------------------------------------------------
usage() {
  echo "Usage: $0 <command> [options]"
  echo ""
  echo "Commands:"
  echo "  export [--space <name>]    Export custom rules from Kibana to local TOML"
  echo "  import [--space <name>]    Import local rules to Kibana"
  echo "  setup-custom               Initialise a custom rules directory"
  echo ""
  echo "Environment variables (or .env file):"
  echo "  KIBANA_ENDPOINT            Kibana URL (default: http://localhost:5601)"
  echo "  KIBANA_USERNAME            Kibana user (default: elastic)"
  echo "  KIBANA_PASSWORD            Kibana password (default: changeme)"
}

# ---- Main --------------------------------------------------------------------
case "${1:-}" in
  export)
    shift
    space="default"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --space) space="$2"; shift 2 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
      esac
    done
    cmd_export "$space"
    ;;
  import)
    shift
    space="default"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --space) space="$2"; shift 2 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
      esac
    done
    cmd_import "$space"
    ;;
  setup-custom)
    cmd_setup_custom
    ;;
  *)
    usage
    exit 1
    ;;
esac
