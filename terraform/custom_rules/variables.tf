# =============================================================================
# custom_rules — Shared variables
# =============================================================================
# These are passed in from the root module so every rule file can reference
# them without repetition.
# =============================================================================

variable "space_id" {
  description = "Kibana space ID (passed from root)."
  type        = string
  default     = "default"
}

variable "default_tags" {
  description = "Tags appended to every rule by the detection_rule module."
  type        = list(string)
  default     = ["detection-as-code", "terraform-managed"]
}

variable "default_enabled" {
  description = "Default enabled state for rules.  Individual rules can override with enabled = true/false."
  type        = bool
  default     = true
}
