# =============================================================================
# Prebuilt Detection Rules — Elastic Vendor-Provided
# =============================================================================
# Installs Elastic's prebuilt detection rules (maintained by Elastic's Threat
# Research team at https://github.com/elastic/detection-rules).
#
# This resource installs and keeps prebuilt rules up to date.  Enablement of
# individual prebuilt rules is managed in Kibana's Rules UI, which provides
# filtering, bulk actions, and tag-based selection purpose-built for this.
# False-positive suppression for enabled prebuilt rules should be handled
# via exception lists in terraform/exceptions/.
#
# Resource docs:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_install_prebuilt_rules
# =============================================================================

resource "elasticstack_kibana_install_prebuilt_rules" "elastic" {
  count    = var.install_prebuilt_rules ? 1 : 0
  space_id = var.kibana_space_id
}
