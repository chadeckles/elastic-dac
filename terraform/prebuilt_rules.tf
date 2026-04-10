# =============================================================================
# Prebuilt Detection Rules — Elastic Vendor-Provided
# =============================================================================
# Installs and enables Elastic's prebuilt detection rules.  These are
# maintained by Elastic's Threat Research team in:
#   https://github.com/elastic/detection-rules
#
# This resource installs ALL available prebuilt rules and keeps them updated.
# Individual rules are then selectively enabled below by tag.
#
# Resource docs:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_install_prebuilt_rules
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_enable_rule
# =============================================================================

# ---------------------------------------------------------------------------
# Install / update all prebuilt rules
# ---------------------------------------------------------------------------
resource "elasticstack_kibana_install_prebuilt_rules" "elastic" {
  count    = var.install_prebuilt_rules ? 1 : 0
  space_id = var.kibana_space_id
}

# ---------------------------------------------------------------------------
# Enable prebuilt rules by OS platform
# ---------------------------------------------------------------------------
# Each block enables all prebuilt rules that carry the given tag.
# Add or remove blocks as needed for your environment.
#
# Docs: Rules are tagged by Elastic with "OS: Windows", "OS: Linux", etc.
# See:  https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_enable_rule
# ---------------------------------------------------------------------------

# Windows endpoint rules
#   Covers: credential access, execution, lateral movement, persistence, etc.
#   NOTE: Bulk enable-by-tag can timeout in small Docker environments with
#         1000+ prebuilt rules. Uncomment when running against a production
#         cluster or enable rules manually in Kibana UI.
# resource "elasticstack_kibana_security_enable_rule" "enable_windows" {
#   count    = var.install_prebuilt_rules ? 1 : 0
#   space_id = var.kibana_space_id
#   key      = "OS"
#   value    = "Windows"
#
#   depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
# }

# Linux endpoint rules
#   Covers: persistence, privilege escalation, defense evasion, etc.
# resource "elasticstack_kibana_security_enable_rule" "enable_linux" {
#   count    = var.install_prebuilt_rules ? 1 : 0
#   space_id = var.kibana_space_id
#   key      = "OS"
#   value    = "Linux"
#
#   depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
# }

# macOS endpoint rules
#   Covers: execution, persistence, collection, etc.
# resource "elasticstack_kibana_security_enable_rule" "enable_macos" {
#   count    = var.install_prebuilt_rules ? 1 : 0
#   space_id = var.kibana_space_id
#   key      = "OS"
#   value    = "macOS"
#
#   depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
# }

# ---------------------------------------------------------------------------
# (Optional) Enable by data source — uncomment as needed
# ---------------------------------------------------------------------------
# resource "elasticstack_kibana_security_enable_rule" "enable_elastic_defend" {
#   count    = var.install_prebuilt_rules ? 1 : 0
#   space_id = var.kibana_space_id
#   key      = "Data Source"
#   value    = "Elastic Defend"
#   depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
# }
#
# resource "elasticstack_kibana_security_enable_rule" "enable_aws" {
#   count    = var.install_prebuilt_rules ? 1 : 0
#   space_id = var.kibana_space_id
#   key      = "Data Source"
#   value    = "AWS"
#   depends_on = [elasticstack_kibana_install_prebuilt_rules.elastic]
# }
