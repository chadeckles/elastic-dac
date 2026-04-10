# =============================================================================
# custom_rules — Outputs
# =============================================================================
# Aggregates outputs from all individual rule modules so the root module
# can expose a single map.
# =============================================================================

output "rule_ids" {
  description = "Map of rule module name → Kibana rule_id."
  value = {
    brute_force_login                = module.brute_force_login.rule_id
    suspicious_powershell_encoded    = module.suspicious_powershell_encoded.rule_id
    lateral_movement_remote_services = module.lateral_movement_remote_services.rule_id
    dns_exfiltration                 = module.dns_exfiltration.rule_id
    suspicious_cron_creation         = module.suspicious_cron_creation.rule_id
  }
}
