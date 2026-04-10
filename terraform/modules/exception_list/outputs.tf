# =============================================================================
# Module: exception_list — Outputs
# =============================================================================

output "list_id" {
  description = "The list_id of the created exception list."
  value       = elasticstack_kibana_security_exception_list.this.list_id
}

output "id" {
  description = "The internal Kibana ID of the exception list."
  value       = elasticstack_kibana_security_exception_list.this.id
}

output "item_ids" {
  description = "Map of item_id → internal Kibana ID for each exception item."
  value = {
    for k, v in elasticstack_kibana_security_exception_item.this : k => v.id
  }
}
