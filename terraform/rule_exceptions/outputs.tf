# =============================================================================
# rule_exceptions — Outputs
# =============================================================================

output "rule_exception_item_ids" {
  description = "Map of file/module name → item_ids attached by that file."
  value = {
    brute_force_login_extras = module.brute_force_login_extras.item_ids
  }
}
