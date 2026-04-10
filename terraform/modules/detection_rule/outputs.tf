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
