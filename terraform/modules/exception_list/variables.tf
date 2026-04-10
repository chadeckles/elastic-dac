# =============================================================================
# Module: exception_list — Variables
# =============================================================================

variable "list_id" {
  description = "Human-readable string identifier for the exception list."
  type        = string
}

variable "name" {
  description = "Display name of the exception list."
  type        = string
}

variable "description" {
  description = "Description of the exception list's purpose."
  type        = string
}

variable "type" {
  description = "Exception list type: detection, endpoint, endpoint_trusted_apps, etc."
  type        = string
  default     = "detection"
}

variable "namespace_type" {
  description = "Scope: single (current space) or agnostic (all spaces)."
  type        = string
  default     = "single"
}

variable "os_types" {
  description = "OS types this list applies to (linux, macos, windows)."
  type        = set(string)
  default     = null
}

variable "tags" {
  description = "Tags for the exception list container."
  type        = list(string)
  default     = []
}

variable "space_id" {
  description = "Kibana space ID."
  type        = string
  default     = "default"
}

variable "items" {
  description = "List of exception items belonging to this list."
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
  default = []
}
