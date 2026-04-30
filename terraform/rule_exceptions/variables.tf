# =============================================================================
# rule_exceptions — Shared variables
# =============================================================================

variable "space_id" {
  description = "Kibana space ID (passed from root)."
  type        = string
  default     = "default"
}

# Outputs from sibling child modules that this directory references.
# Wired in main.tf so each rule_exceptions/*.tf file can address rules by
# their module name (e.g. var.rule_default_lists[\"brute_force_login\"]).
variable "rule_default_lists" {
  description = "Map of rule module name → rule_default_exception_list_id."
  type        = map(string)
  default     = {}
}
