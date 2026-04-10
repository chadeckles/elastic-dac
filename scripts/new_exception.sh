#!/usr/bin/env bash
# =============================================================================
# new_exception.sh — Interactive wizard to create a new exception list
# =============================================================================
# Prompts for exception details in plain English and generates:
#   1. A numbered .tf file in terraform/exceptions/
#   2. An updated outputs.tf with the new module registered
#
# Usage:
#   make new-exception     (recommended)
#   bash scripts/new_exception.sh
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EXCEPTIONS_DIR="$PROJECT_ROOT/terraform/exceptions"
OUTPUTS_FILE="$EXCEPTIONS_DIR/outputs.tf"

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

to_kebab_case() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-//; s/-$//'
}

get_next_number() {
    local last
    last=$(ls "$EXCEPTIONS_DIR"/[0-9]*.tf 2>/dev/null | sort | tail -1 | grep -oE '[0-9]+' | head -1)
    if [[ -z "$last" ]]; then
        echo "001"
    else
        printf "%03d" $((10#$last + 1))
    fi
}

esc() { echo "$1" | sed 's/"/\\"/g'; }

# =============================================================================
# Main
# =============================================================================
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  New Exception List Wizard${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Answer the prompts below to create an exception list."
echo -e "  You can add one or more exception items."
echo ""

# ---- List details ----------------------------------------------------------
prompt_required LIST_NAME "Exception list name (e.g. Trusted Internal Scanners)"
prompt_required LIST_DESC "Description (what false positives does this suppress?)"
prompt TAG_CSV "Tags (comma-separated, optional)" ""

# ---- Compute names ---------------------------------------------------------
SNAKE_NAME=$(to_snake_case "$LIST_NAME")
KEBAB_NAME=$(to_kebab_case "$LIST_NAME")

# ---- Exception items -------------------------------------------------------
echo ""
echo -e "${BOLD}Now add exception items.  You need at least one.${NC}"
echo -e "Each item matches specific field values to suppress false positives."
echo ""

ITEMS=()
ITEM_NUM=0

while true; do
    ITEM_NUM=$((ITEM_NUM + 1))
    echo -e "${BOLD}── Exception Item #${ITEM_NUM} ──${NC}"
    prompt_required ITEM_NAME "Item name (e.g. Nessus Scanner)"
    prompt_required ITEM_DESC "Item description (why is this excepted?)"

    ITEM_SNAKE=$(to_snake_case "$ITEM_NAME")
    ITEM_KEBAB=$(to_kebab_case "$ITEM_NAME")

    # Entries (field conditions)
    echo ""
    echo -e "  ${BOLD}Add field conditions for this item:${NC}"
    ENTRIES=()
    ENTRY_NUM=0
    while true; do
        ENTRY_NUM=$((ENTRY_NUM + 1))
        echo ""
        prompt_required FIELD_NAME  "  Field name (e.g. host.name, source.ip, process.name)"
        prompt_required FIELD_VALUE "  Value to match (e.g. nessus-scanner, 10.0.0.0/8)"
        prompt_choice MATCH_TYPE "  Match type" "match,match_any,exists,list,wildcard" "match"
        prompt_choice OPERATOR   "  Operator"   "included,excluded" "included"

        ENTRIES+=("ENTRY:${FIELD_NAME}:${MATCH_TYPE}:${OPERATOR}:${FIELD_VALUE}")

        printf "\n  ${CYAN}Add another field condition to this item?${NC} (${YELLOW}y/n${NC}) [${YELLOW}n${NC}]: "
        read -r more_entries
        [[ "$more_entries" =~ ^[Yy] ]] || break
    done

    # Store item
    ITEMS+=("ITEM:${ITEM_SNAKE}:${ITEM_KEBAB}:$(esc "$ITEM_NAME"):$(esc "$ITEM_DESC"):${#ENTRIES[@]}")
    for e in "${ENTRIES[@]}"; do
        ITEMS+=("$e")
    done

    echo ""
    printf "${CYAN}Add another exception item?${NC} (${YELLOW}y/n${NC}) [${YELLOW}n${NC}]: "
    read -r more_items
    [[ "$more_items" =~ ^[Yy] ]] || break
done

# ---- Compute file name ---------------------------------------------------
NEXT_NUM=$(get_next_number)
FILE_NAME="${NEXT_NUM}_${SNAKE_NAME}.tf"
MODULE_NAME="${SNAKE_NAME}"

# ---- Generate .tf file ----------------------------------------------------
echo ""
echo -e "${BOLD}Generating ${GREEN}$FILE_NAME${NC}…"

{
    echo "# ============================================================================="
    echo "# ${LIST_NAME}"
    echo "# ============================================================================="
    echo "# $(echo "$LIST_DESC" | fold -s -w 75)"
    echo "# ============================================================================="
    echo ""
    echo "module \"${MODULE_NAME}\" {"
    echo "  source = \"../modules/exception_list\""
    echo ""
    echo "  list_id     = \"${KEBAB_NAME}\""
    echo "  name        = \"$(esc "$LIST_NAME")\""
    echo "  description = \"$(esc "$LIST_DESC")\""
    echo "  type        = \"detection\""

    # Tags
    if [[ -n "$TAG_CSV" ]]; then
        echo "  tags        = ["
        IFS=',' read -ra TAG_ARRAY <<< "$TAG_CSV"
        for tag in "${TAG_ARRAY[@]}"; do
            tag=$(echo "$tag" | xargs)
            echo "    \"${tag}\","
        done
        echo "  ]"
    fi

    # Items
    echo ""
    echo "  items = ["

    local_idx=0
    for token in "${ITEMS[@]}"; do
        IFS=':' read -ra PARTS <<< "$token"
        if [[ "${PARTS[0]}" == "ITEM" ]]; then
            [[ $local_idx -gt 0 ]] && echo ""
            local_idx=$((local_idx + 1))
            echo "    {"
            echo "      item_id     = \"${PARTS[2]}\""
            echo "      name        = \"${PARTS[3]}\""
            echo "      description = \"${PARTS[4]}\""
            echo "      tags        = []"
            echo "      entries = ["
        elif [[ "${PARTS[0]}" == "ENTRY" ]]; then
            echo "        {"
            echo "          field    = \"${PARTS[1]}\""
            echo "          type     = \"${PARTS[2]}\""
            echo "          operator = \"${PARTS[3]}\""
            echo "          value    = \"${PARTS[4]}\""
            echo "        },"
            # Check if this is the last entry for the current item
            # (peek ahead — if next token is ITEM or end, close entries+item)
        fi
    done

    # Close the last item
    echo "      ]"
    echo "    },"
    echo "  ]"
    echo ""
    echo "  space_id = var.space_id"
    echo "}"

} > "$EXCEPTIONS_DIR/$FILE_NAME"

# Fix item boundaries: we need to close entries/item before each new ITEM token
# Simpler approach: rewrite with proper structure using a Python one-liner
# Actually the above sequential approach leaves entries/items open.
# Let's fix by regenerating properly:

{
    echo "# ============================================================================="
    echo "# ${LIST_NAME}"
    echo "# ============================================================================="
    echo "# $(echo "$LIST_DESC" | fold -s -w 75)"
    echo "# ============================================================================="
    echo ""
    echo "module \"${MODULE_NAME}\" {"
    echo "  source = \"../modules/exception_list\""
    echo ""
    echo "  list_id     = \"${KEBAB_NAME}\""
    echo "  name        = \"$(esc "$LIST_NAME")\""
    echo "  description = \"$(esc "$LIST_DESC")\""
    echo "  type        = \"detection\""

    if [[ -n "$TAG_CSV" ]]; then
        echo "  tags        = ["
        IFS=',' read -ra TAG_ARRAY <<< "$TAG_CSV"
        for tag in "${TAG_ARRAY[@]}"; do
            tag=$(echo "$tag" | xargs)
            echo "    \"${tag}\","
        done
        echo "  ]"
    fi

    echo ""
    echo "  items = ["

    in_item=false
    for token in "${ITEMS[@]}"; do
        IFS=':' read -ra PARTS <<< "$token"
        if [[ "${PARTS[0]}" == "ITEM" ]]; then
            if $in_item; then
                # Close previous item
                echo "      ]"
                echo "    },"
            fi
            in_item=true
            echo "    {"
            echo "      item_id     = \"${PARTS[2]}\""
            echo "      name        = \"${PARTS[3]}\""
            echo "      description = \"${PARTS[4]}\""
            echo "      tags        = []"
            echo "      entries = ["
        elif [[ "${PARTS[0]}" == "ENTRY" ]]; then
            echo "        {"
            echo "          field    = \"${PARTS[1]}\""
            echo "          type     = \"${PARTS[2]}\""
            echo "          operator = \"${PARTS[3]}\""
            echo "          value    = \"${PARTS[4]}\""
            echo "        },"
        fi
    done
    # Close the last item
    if $in_item; then
        echo "      ]"
        echo "    },"
    fi

    echo "  ]"
    echo ""
    echo "  space_id = var.space_id"
    echo "}"

} > "$EXCEPTIONS_DIR/$FILE_NAME"

echo -e "  ${GREEN}✓ Created:${NC} terraform/exceptions/$FILE_NAME"

# ---- Update outputs.tf ----------------------------------------------------
PADDED_NAME=$(printf "%-40s" "$MODULE_NAME")
NEW_LINE="    ${PADDED_NAME}= module.${MODULE_NAME}.list_id"

if grep -q "module\\..*\\.list_id" "$OUTPUTS_FILE"; then
    LAST_MODULE_LINE=$(grep -n "module\\..*\\.list_id" "$OUTPUTS_FILE" | tail -1 | cut -d: -f1)
    sed -i '' "${LAST_MODULE_LINE}a\\
${NEW_LINE}" "$OUTPUTS_FILE"
    echo -e "  ${GREEN}✓ Updated:${NC} terraform/exceptions/outputs.tf"
else
    echo -e "  ${YELLOW}⚠ Could not auto-update outputs.tf — please add manually:${NC}"
    echo "    $NEW_LINE"
fi

# ---- Summary ---------------------------------------------------------------
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Exception list created successfully!${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}File:${NC}    terraform/exceptions/$FILE_NAME"
echo -e "  ${BOLD}Module:${NC}  $MODULE_NAME"
echo -e "  ${BOLD}Items:${NC}   $ITEM_NUM"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. ${CYAN}make test${NC}    ← Validate your exception"
echo -e "    2. ${CYAN}make plan${NC}    ← Preview changes"
echo -e "    3. ${CYAN}make apply${NC}   ← Deploy to Elastic"
echo ""
