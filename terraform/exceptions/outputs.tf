# =============================================================================
# exceptions — Outputs
# =============================================================================

output "exception_list_ids" {
  description = "Map of exception module name → list_id."
  value = {
    trusted_infrastructure = module.trusted_infrastructure.list_id
    approved_powershell    = module.approved_powershell.list_id
    dns_allowlist          = module.dns_allowlist.list_id
    approved_cron          = module.approved_cron.list_id
  }
}
