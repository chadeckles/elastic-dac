# =============================================================================
# Module: rule_exception_items — Outputs
# =============================================================================

output "item_ids" {
  description = "Map of item_id → internal Kibana ID for each created exception item."
  value       = { for k, v in elasticstack_kibana_security_exception_item.this : k => v.id }
}

output "list_id" {
  description = "list_id the items were attached to (passthrough)."
  value       = var.list_id
}
