# =============================================================================
# Root Outputs
# =============================================================================

output "prebuilt_rules_installed" {
  description = "Number of Elastic prebuilt rules installed."
  value       = var.install_prebuilt_rules ? elasticstack_kibana_install_prebuilt_rules.elastic[0].rules_installed : 0
}

output "custom_rule_ids" {
  description = "Map of custom detection rule names → rule IDs."
  value       = module.custom_rules.rule_ids
}

output "exception_list_ids" {
  description = "Map of exception list names → list IDs."
  value       = module.exceptions.exception_list_ids
}

output "environment" {
  description = "Current deployment environment."
  value       = var.environment
}
