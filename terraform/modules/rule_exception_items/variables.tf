# =============================================================================
# Module: rule_exception_items — Variables
# =============================================================================

variable "list_id" {
  description = <<-EOT
    list_id of the EXISTING exception list these items will belong to.
    Typically the `rule_default_exception_list_id` output of a detection_rule
    module call, or the list_id of a Kibana-managed exception list.
  EOT
  type        = string
}

variable "namespace_type" {
  description = "Scope: `single` (current space) or `agnostic` (all spaces)."
  type        = string
  default     = "single"
}

variable "space_id" {
  description = "Kibana space ID."
  type        = string
  default     = "default"
}

variable "items" {
  description = "List of exception items to create on the target list."
  type = list(object({
    item_id     = string
    name        = string
    description = string
    type        = optional(string, "simple")
    os_types    = optional(set(string))
    tags        = optional(list(string), [])
    expire_time = optional(string)
    entries = list(object({
      field    = string
      type     = string
      operator = optional(string, "included")
      value    = optional(string)
      values   = optional(list(string))
    }))
  }))
}
