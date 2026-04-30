# =============================================================================
# Module: detection_rule — Outputs
# =============================================================================

output "rule_id" {
  description = "The Kibana rule_id of the created detection rule."
  value       = elasticstack_kibana_security_detection_rule.this.rule_id
}

output "id" {
  description = "The internal Kibana ID of the created detection rule."
  value       = elasticstack_kibana_security_detection_rule.this.id
}

output "name" {
  description = "The name of the created detection rule."
  value       = elasticstack_kibana_security_detection_rule.this.name
}

output "rule_default_exception_list_id" {
  description = <<-EOT
    list_id of the rule-scoped exception list created when `rule_exceptions`
    was provided. Useful if you want to add more items to the same list
    from outside the rule file (see modules/rule_exception_items).
  EOT
  value       = local.has_rule_exceptions ? elasticstack_kibana_security_exception_list.rule_default[0].list_id : null
}

output "rule_default_exception_item_ids" {
  description = "Map of item_id → internal Kibana ID for each rule-default exception item."
  value = {
    for k, v in elasticstack_kibana_security_exception_item.rule_default : k => v.id
  }
}
