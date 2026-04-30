# =============================================================================
# Brute-Force Login — Extra rule-scoped exceptions
# =============================================================================
# Demonstrates the production-default pattern: managing kibana_security_exception_item
# resources in a file separate from the rule itself, attached to that rule's
# auto-created rule-default exception list.
#
# The rule file (custom_rules/001_brute_force_login.tf) owns the rule and any
# core exceptions. Analysts can add tuning items here without touching the
# rule resource, so PR reviews stay focused on the right surface.
# =============================================================================

module "brute_force_login_extras" {
  source = "../modules/rule_exception_items"

  # Pulls the list_id from the rule module's `rule_default_exception_list_id`
  # output, threaded through the root module via var.rule_default_lists.
  list_id  = var.rule_default_lists["brute_force_login"]
  space_id = var.space_id

  items = [
    {
      item_id     = "brute-force-jump-host"
      name        = "Internal jump host"
      description = "Bastion host re-uses credentials on every hop, generates noisy auth-failure spikes during patching windows."
      tags        = ["bastion", "false-positive-reduction"]
      entries = [
        {
          field    = "source.ip"
          type     = "match"
          operator = "included"
          value    = "10.0.99.10"
        }
      ]
    },
  ]
}
