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

variable "enabled_prebuilt_rule_tags" {
  description = <<-EOT
    Map of prebuilt rule categories to ENABLE.  Each entry is a tag key/value
    pair that matches Elastic's built-in rule tags.  Rules whose tags are NOT
    listed here will remain installed but disabled.

    Removing an entry disables that category on the next apply.

    Common tag keys: OS, Data Source, Use Case, Tactic, Domain.
    See prebuilt_rules.tf for a full reference of available values.
  EOT
  type = map(object({
    key   = string
    value = string
  }))
  default = {
    # ── OS-based ──────────────────────────────────────────────────────────
    # windows = { key = "OS", value = "Windows" }
    # linux   = { key = "OS", value = "Linux" }
    # macos   = { key = "OS", value = "macOS" }

    # ── Data-source-based ─────────────────────────────────────────────────
    # elastic_defend = { key = "Data Source", value = "Elastic Defend" }
    # aws            = { key = "Data Source", value = "AWS" }
    # azure          = { key = "Data Source", value = "Azure" }
    # gcp            = { key = "Data Source", value = "GCP" }
    # m365           = { key = "Data Source", value = "Microsoft 365" }
    # okta           = { key = "Data Source", value = "Okta" }

    # ── Use-case-based ────────────────────────────────────────────────────
    # threat_detection = { key = "Use Case", value = "Threat Detection" }
    # ueba             = { key = "Use Case", value = "UEBA" }

    # ── MITRE tactic-based ────────────────────────────────────────────────
    # credential_access       = { key = "Tactic", value = "Credential Access" }
    # defense_evasion         = { key = "Tactic", value = "Defense Evasion" }
    # execution               = { key = "Tactic", value = "Execution" }
    # exfiltration            = { key = "Tactic", value = "Exfiltration" }
    # initial_access          = { key = "Tactic", value = "Initial Access" }
    # lateral_movement        = { key = "Tactic", value = "Lateral Movement" }
    # persistence             = { key = "Tactic", value = "Persistence" }
    # privilege_escalation    = { key = "Tactic", value = "Privilege Escalation" }
  }
}
