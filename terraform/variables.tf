# =============================================================================
# Root Variables
# =============================================================================

# ---- Kibana -----------------------------------------------------------------
variable "kibana_api_key" {
  description = <<-EOT
    Base64-encoded Kibana API key (the "encoded" field returned by
    POST /_security/api_key, or the "Encoded" value shown in Kibana → Stack
    Management → API Keys). Leave null to fall back to the KIBANA_API_KEY
    environment variable, which the elasticstack provider also honours
    automatically.
  EOT
  type        = string
  sensitive   = true
  default     = null
}

variable "kibana_endpoint" {
  description = <<-EOT
    Kibana endpoint (include scheme and port). On Elastic Cloud this is the
    URL in your browser address bar when on Stack Management. Falls back to
    KIBANA_ENDPOINT env var.
  EOT
  type        = string
  default     = null
}

# ---- General ----------------------------------------------------------------
variable "kibana_space_id" {
  description = "Kibana space in which to deploy detection rules. Defaults to 'dac', the staging space for Detection-as-Code managed content."
  type        = string
  default     = "dac"
}

variable "environment" {
  description = "Deployment environment label (dev, staging, prod)."
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "default_rule_tags" {
  description = "Default tags applied to every custom detection rule."
  type        = list(string)
  default     = ["detection-as-code", "terraform-managed"]
}

variable "default_enabled" {
  description = "Default enabled state for new custom rules.  Set to false in prod to prevent new rules from firing before review."
  type        = bool
  default     = true
}

variable "install_prebuilt_rules" {
  description = "Whether to install/update Elastic prebuilt detection rules."
  type        = bool
  default     = true
}
