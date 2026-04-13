#!/usr/bin/env bash
# =============================================================================
# new_rule.sh — Interactive wizard to create a new detection rule
# =============================================================================
# Prompts for rule details in plain English and generates:
#   1. A numbered .tf file in terraform/custom_rules/
#   2. An updated outputs.tf with the new module registered
#
# Usage:
#   make new-rule          (recommended)
#   bash scripts/new_rule.sh
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RULES_DIR="$PROJECT_ROOT/terraform/custom_rules"
OUTPUTS_FILE="$RULES_DIR/outputs.tf"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic lookup (bash 3.x compatible — no associative arrays)
# ---------------------------------------------------------------------------
lookup_tactic() {
    local id="$1"
    case "$id" in
        TA0001) PICKED_TACTIC_NAME="Initial Access";       PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0001/" ;;
        TA0002) PICKED_TACTIC_NAME="Execution";            PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0002/" ;;
        TA0003) PICKED_TACTIC_NAME="Persistence";          PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0003/" ;;
        TA0004) PICKED_TACTIC_NAME="Privilege Escalation"; PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0004/" ;;
        TA0005) PICKED_TACTIC_NAME="Defense Evasion";      PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0005/" ;;
        TA0006) PICKED_TACTIC_NAME="Credential Access";    PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0006/" ;;
        TA0007) PICKED_TACTIC_NAME="Discovery";            PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0007/" ;;
        TA0008) PICKED_TACTIC_NAME="Lateral Movement";     PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0008/" ;;
        TA0009) PICKED_TACTIC_NAME="Collection";           PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0009/" ;;
        TA0010) PICKED_TACTIC_NAME="Exfiltration";         PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0010/" ;;
        TA0011) PICKED_TACTIC_NAME="Command and Control";  PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0011/" ;;
        TA0040) PICKED_TACTIC_NAME="Impact";               PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0040/" ;;
        TA0042) PICKED_TACTIC_NAME="Resource Development"; PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0042/" ;;
        TA0043) PICKED_TACTIC_NAME="Reconnaissance";       PICKED_TACTIC_URL="https://attack.mitre.org/tactics/TA0043/" ;;
        *) return 1 ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
prompt() {
    local var_name="$1" prompt_text="$2" default="${3:-}"
    local input
    if [[ -n "$default" ]]; then
        printf "${CYAN}%s${NC} [${YELLOW}%s${NC}]: " "$prompt_text" "$default"
    else
        printf "${CYAN}%s${NC}: " "$prompt_text"
    fi
    read -r input
    input="${input:-$default}"
    eval "$var_name=\"\$input\""
}

prompt_required() {
    local var_name="$1" prompt_text="$2"
    local input=""
    while [[ -z "$input" ]]; do
        printf "${CYAN}%s${NC} (required): " "$prompt_text"
        read -r input
        [[ -z "$input" ]] && echo -e "  ${RED}This field is required.${NC}"
    done
    eval "$var_name=\"\$input\""
}

prompt_choice() {
    local var_name="$1" prompt_text="$2" choices="$3" default="$4"
    local input=""
    while true; do
        printf "${CYAN}%s${NC} (${YELLOW}%s${NC}) [${YELLOW}%s${NC}]: " "$prompt_text" "$choices" "$default"
        read -r input
        input="${input:-$default}"
        if echo ",$choices," | grep -qi ",$input,"; then
            eval "$var_name=\"\$input\""
            return
        fi
        echo -e "  ${RED}Please choose one of: $choices${NC}"
    done
}

to_snake_case() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g; s/^_//; s/_$//'
}

# ---------------------------------------------------------------------------
# Find next rule number
# ---------------------------------------------------------------------------
get_next_number() {
    local last
    last=$(ls "$RULES_DIR"/[0-9]*.tf 2>/dev/null | sort | tail -1 | grep -oE '[0-9]+' | head -1)
    if [[ -z "$last" ]]; then
        echo "001"
    else
        printf "%03d" $((10#$last + 1))
    fi
}

# ---------------------------------------------------------------------------
# MITRE tactic picker
# ---------------------------------------------------------------------------
pick_tactic() {
    echo ""
    echo -e "${BOLD}Available MITRE ATT&CK Tactics:${NC}"
    echo "  TA0001  Initial Access         TA0008  Lateral Movement"
    echo "  TA0002  Execution              TA0009  Collection"
    echo "  TA0003  Persistence            TA0010  Exfiltration"
    echo "  TA0004  Privilege Escalation   TA0011  Command and Control"
    echo "  TA0005  Defense Evasion        TA0040  Impact"
    echo "  TA0006  Credential Access      TA0042  Resource Development"
    echo "  TA0007  Discovery              TA0043  Reconnaissance"
    echo ""

    local tactic_id=""
    while true; do
        printf "${CYAN}MITRE Tactic ID${NC} (e.g. TA0001): "
        read -r tactic_id
        tactic_id=$(echo "$tactic_id" | tr '[:lower:]' '[:upper:]')
        if lookup_tactic "$tactic_id"; then
            PICKED_TACTIC_ID="$tactic_id"
            echo -e "  ${GREEN}✓ ${PICKED_TACTIC_NAME}${NC}"
            return
        fi
        echo -e "  ${RED}Unknown tactic ID. Please pick from the list above.${NC}"
    done
}

# ---------------------------------------------------------------------------
# Technique prompt (optional)
# ---------------------------------------------------------------------------
pick_technique() {
    echo ""
    printf "${CYAN}MITRE Technique ID${NC} (e.g. T1059 — press Enter to skip): "
    read -r TECH_ID
    if [[ -z "$TECH_ID" ]]; then
        HAS_TECHNIQUE=false
        return
    fi
    TECH_ID=$(echo "$TECH_ID" | tr '[:lower:]' '[:upper:]')
    HAS_TECHNIQUE=true
    prompt_required TECH_NAME "Technique name (e.g. Command and Scripting Interpreter)"
    TECH_URL="https://attack.mitre.org/techniques/${TECH_ID}/"

    # Sub-technique
    echo ""
    printf "${CYAN}Sub-technique ID${NC} (e.g. T1059.001 — press Enter to skip): "
    read -r SUB_ID
    if [[ -n "$SUB_ID" ]]; then
        SUB_ID=$(echo "$SUB_ID" | tr '[:lower:]' '[:upper:]')
        HAS_SUBTECHNIQUE=true
        prompt_required SUB_NAME "Sub-technique name (e.g. PowerShell)"
        SUB_URL="https://attack.mitre.org/techniques/${SUB_ID//.//}/"
    else
        HAS_SUBTECHNIQUE=false
    fi
}

# =============================================================================
# Main
# =============================================================================
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  New Detection Rule Wizard${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Answer the prompts below. Defaults are shown in ${YELLOW}yellow${NC}."
echo -e "  A complete .tf file will be generated for you."
echo ""

# ---- Core fields ----------------------------------------------------------
prompt_required RULE_NAME "Rule name (e.g. Suspicious SSH Key Creation)"
prompt_required RULE_DESC "Description (one sentence — what does this detect?)"

echo ""
prompt_choice RULE_TYPE   "Rule type"  "query,eql,threshold,esql,new_terms,threat_match,machine_learning"  "query"
prompt_choice SEVERITY    "Severity"   "low,medium,high,critical"  "medium"
prompt          RISK_SCORE "Risk score (0–100)" "50"
prompt_choice LANGUAGE    "Query language" "kuery,eql,esql,lucene" "kuery"

echo ""
echo -e "${BOLD}Enter your detection query.${NC} For multi-line EQL, type each line"
echo -e "and press Enter. Type ${YELLOW}END${NC} on a line by itself when done."
echo ""
printf "${CYAN}Query${NC}: "
QUERY_LINES=()
while IFS= read -r line; do
    [[ "$line" == "END" || "$line" == "end" ]] && break
    QUERY_LINES+=("$line")
    [[ ${#QUERY_LINES[@]} -eq 1 ]] && printf "       " || true
done
QUERY=$(printf '%s\n' "${QUERY_LINES[@]}")

# ---- Index patterns -------------------------------------------------------
echo ""
prompt INDEX_CSV "Index patterns (comma-separated)" "logs-*"
IFS=',' read -ra INDEX_ARRAY <<< "$INDEX_CSV"

# ---- Team & tags -----------------------------------------------------------
echo ""
prompt_required TEAM_NAME "Team name for SOC routing (e.g. SOC, Threat Intel, Infrastructure)"
prompt TAG_CSV "Additional tags (comma-separated, optional)" ""

# ---- MITRE ATT&CK ---------------------------------------------------------
pick_tactic
pick_technique

# ---- False positives -------------------------------------------------------
echo ""
prompt FP_CSV "Known false positives (comma-separated, optional)" ""

# ---- Enabled ---------------------------------------------------------------
echo ""
prompt_choice ENABLED "Enable this rule immediately?" "yes,no" "no"
[[ "$ENABLED" == "yes" ]] && ENABLED_VALUE="true" || ENABLED_VALUE="var.default_enabled"

# ---- Compute file names ---------------------------------------------------
NEXT_NUM=$(get_next_number)
SNAKE_NAME=$(to_snake_case "$RULE_NAME")
FILE_NAME="${NEXT_NUM}_${SNAKE_NAME}.tf"
MODULE_NAME="${SNAKE_NAME}"

# ---- Build the .tf file ---------------------------------------------------
echo ""
echo -e "${BOLD}Generating ${GREEN}$FILE_NAME${NC}…"

# Escape double-quotes in user input
esc() { echo "$1" | sed 's/"/\\"/g'; }

cat > "$RULES_DIR/$FILE_NAME" << RULEEOF
# =============================================================================
# ${RULE_NAME}
# =============================================================================
# $(echo "$RULE_DESC" | fold -s -w 73 | sed 's/^/# /' | tail -n +2)
#
# MITRE ATT&CK:  ${PICKED_TACTIC_ID} ${PICKED_TACTIC_NAME}$(if $HAS_TECHNIQUE; then echo " → ${TECH_ID} ${TECH_NAME}"; fi)
# Team:          ${TEAM_NAME}
# =============================================================================

module "${MODULE_NAME}" {
  source = "../modules/detection_rule"

  name        = "$(esc "$RULE_NAME")"
  description = "$(esc "$RULE_DESC")"
  type        = "${RULE_TYPE}"
  severity    = "${SEVERITY}"
  risk_score  = ${RISK_SCORE}

RULEEOF

# Query — single-line or heredoc
if [[ ${#QUERY_LINES[@]} -eq 1 ]]; then
    cat >> "$RULES_DIR/$FILE_NAME" << RULEEOF
  query    = "$(esc "$QUERY")"
  language = "${LANGUAGE}"
RULEEOF
else
    cat >> "$RULES_DIR/$FILE_NAME" << RULEEOF
  query = <<-EOQ
    ${QUERY}
  EOQ

  language = "${LANGUAGE}"
RULEEOF
fi

# Index patterns
{
    echo ""
    echo "  index = ["
    for idx in "${INDEX_ARRAY[@]}"; do
        idx=$(echo "$idx" | xargs)   # trim whitespace
        echo "    \"${idx}\","
    done
    echo "  ]"
} >> "$RULES_DIR/$FILE_NAME"

# Tags
{
    echo ""
    echo "  tags = ["
    # Additional user tags
    if [[ -n "$TAG_CSV" ]]; then
        IFS=',' read -ra TAG_ARRAY <<< "$TAG_CSV"
        for tag in "${TAG_ARRAY[@]}"; do
            tag=$(echo "$tag" | xargs)
            echo "    \"${tag}\","
        done
    fi
    echo "    \"Team: ${TEAM_NAME}\","
    echo "  ]"
} >> "$RULES_DIR/$FILE_NAME"

# False positives
if [[ -n "$FP_CSV" ]]; then
    {
        echo ""
        echo "  false_positives = ["
        IFS=',' read -ra FP_ARRAY <<< "$FP_CSV"
        for fp in "${FP_ARRAY[@]}"; do
            fp=$(echo "$fp" | xargs)
            echo "    \"$(esc "$fp")\","
        done
        echo "  ]"
    } >> "$RULES_DIR/$FILE_NAME"
fi

# MITRE threat mapping
{
    echo ""
    echo "  threat = ["
    echo "    {"
    echo "      tactic = {"
    echo "        id        = \"${PICKED_TACTIC_ID}\""
    echo "        name      = \"${PICKED_TACTIC_NAME}\""
    echo "        reference = \"${PICKED_TACTIC_URL}\""
    echo "      }"
    if $HAS_TECHNIQUE; then
        echo "      technique = ["
        echo "        {"
        echo "          id        = \"${TECH_ID}\""
        echo "          name      = \"$(esc "$TECH_NAME")\""
        echo "          reference = \"${TECH_URL}\""
        if $HAS_SUBTECHNIQUE; then
            echo "          subtechnique = ["
            echo "            {"
            echo "              id        = \"${SUB_ID}\""
            echo "              name      = \"$(esc "$SUB_NAME")\""
            echo "              reference = \"${SUB_URL}\""
            echo "            }"
            echo "          ]"
        else
            echo "          subtechnique = []"
        fi
        echo "        }"
        echo "      ]"
    else
        echo "      technique = []"
    fi
    echo "    }"
    echo "  ]"
} >> "$RULES_DIR/$FILE_NAME"

# Threshold stub if threshold type
if [[ "$RULE_TYPE" == "threshold" ]]; then
    {
        echo ""
        echo "  threshold = {"
        echo "    field = [\"source.ip\"]    # ← Change to your group-by field"
        echo "    value = 10                # ← Change to your threshold count"
        echo "  }"
    } >> "$RULES_DIR/$FILE_NAME"
fi

# Enabled + shared vars
{
    echo ""
    echo "  # ---- Toggle (inherit directory default or override per-rule) --------"
    if [[ "$ENABLED_VALUE" == "true" ]]; then
        echo "  enabled = true                # Override: always enabled"
    else
        echo "  enabled = var.default_enabled     # Inherits directory default"
    fi
    echo ""
    echo "  space_id     = var.space_id"
    echo "  default_tags = var.default_tags"
    echo "}"
} >> "$RULES_DIR/$FILE_NAME"

echo -e "  ${GREEN}✓ Created:${NC} terraform/custom_rules/$FILE_NAME"

# ---- Update outputs.tf ----------------------------------------------------
# Insert a new line into the value map before the closing brace
PADDED_NAME=$(printf "%-40s" "$MODULE_NAME")
NEW_LINE="    ${PADDED_NAME}= module.${MODULE_NAME}.rule_id"

# Find the last module reference line and append after it
if grep -q "module\\..*\\.rule_id" "$OUTPUTS_FILE"; then
    # Use the last existing module line as anchor
    LAST_MODULE_LINE=$(grep -n "module\\..*\\.rule_id" "$OUTPUTS_FILE" | tail -1 | cut -d: -f1)
    sed -i '' "${LAST_MODULE_LINE}a\\
${NEW_LINE}" "$OUTPUTS_FILE"
    echo -e "  ${GREEN}✓ Updated:${NC} terraform/custom_rules/outputs.tf"
else
    echo -e "  ${YELLOW}⚠ Could not auto-update outputs.tf — please add manually:${NC}"
    echo "    $NEW_LINE"
fi

# ---- Summary ---------------------------------------------------------------
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Rule created successfully!${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}File:${NC}     terraform/custom_rules/$FILE_NAME"
echo -e "  ${BOLD}Module:${NC}   $MODULE_NAME"
echo -e "  ${BOLD}Enabled:${NC}  $ENABLED_VALUE"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. ${CYAN}make test${NC}    ← Validate your rule"
echo -e "    2. ${CYAN}make plan${NC}    ← Preview changes"
echo -e "    3. ${CYAN}make apply${NC}   ← Deploy to Elastic"
echo ""
