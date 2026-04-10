# =============================================================================
# Prebuilt Detection Rules — Elastic Vendor-Provided
# =============================================================================
# Installs Elastic's prebuilt detection rules (maintained by Elastic's Threat
# Research team at https://github.com/elastic/detection-rules).
#
# ENABLE/DISABLE is driven entirely by `var.enabled_prebuilt_rule_tags`.
# - Adding an entry to the map  → enables that rule category on next apply.
# - Removing an entry           → disables it (via disable_on_destroy).
# - Empty map                   → all prebuilt rules remain installed but disabled.
#
# Resource docs:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_install_prebuilt_rules
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_enable_rule
# =============================================================================

# ---------------------------------------------------------------------------
# Install / update all prebuilt rules (does NOT enable them)
# ---------------------------------------------------------------------------
resource "elasticstack_kibana_install_prebuilt_rules" "elastic" {
  count    = var.install_prebuilt_rules ? 1 : 0
  space_id = var.kibana_space_id
}

# ---------------------------------------------------------------------------
# Selectively enable prebuilt rules by tag
# ---------------------------------------------------------------------------
# This single resource block replaces all hardcoded enable blocks.
# It iterates over var.enabled_prebuilt_rule_tags — the ONLY source of truth
# for which prebuilt rule categories are active.
#
# Available tag keys and example values (from Elastic's tagging):
#
#   Key             Example values
#   ──────────────  ────────────────────────────────────────────────
#   OS              Windows, Linux, macOS
#   Data Source     Elastic Defend, Elastic Endgame, AWS,
#                   Azure, GCP, Google Workspace, Microsoft 365,
#                   Okta, GitHub, Network, APM
#   Use Case        Threat Detection, UEBA, Asset Visibility,
#                   Log Auditing, Identity and Access Audit
#   Tactic          Credential Access, Defense Evasion, Discovery,
#                   Execution, Exfiltration, Impact, Initial Access,
#                   Lateral Movement, Persistence, Privilege Escalation,
#                   Collection, Command and Control, Reconnaissance,
#                   Resource Development
#   Domain          Endpoint, Cloud, Network
# ---------------------------------------------------------------------------
resource "elasticstack_kibana_security_enable_rule" "prebuilt" {
  for_each = var.install_prebuilt_rules ? var.enabled_prebuilt_rule_tags : {}

  space_id           = var.kibana_space_id
  key                = each.value.key
  value              = each.value.value
  disable_on_destroy = true

  depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
}
#   depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
# }
