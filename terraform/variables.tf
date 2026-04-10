# =============================================================================
# Root Variables
# =============================================================================

# ---- Elasticsearch ----------------------------------------------------------
variable "elasticsearch_username" {
  description = "Username for Elasticsearch authentication."
  type        = string
  default     = "elastic"
}

variable "elasticsearch_password" {
  description = "Password for Elasticsearch authentication."
  type        = string
  sensitive   = true
  default     = "changeme"
}

variable "elasticsearch_endpoints" {
  description = "List of Elasticsearch endpoints (include scheme and port)."
  type        = list(string)
  default     = ["http://localhost:9200"]
}

# ---- Kibana -----------------------------------------------------------------
variable "kibana_username" {
  description = "Username for Kibana authentication."
  type        = string
  default     = "elastic"
}

variable "kibana_password" {
  description = "Password for Kibana authentication."
  type        = string
  sensitive   = true
  default     = "changeme"
}

variable "kibana_endpoint" {
  description = "Kibana endpoint (include scheme and port)."
  type        = string
  default     = "http://localhost:5601"
}

# ---- General ----------------------------------------------------------------
variable "kibana_space_id" {
  description = "Kibana space in which to deploy detection rules."
  type        = string
  default     = "default"
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
