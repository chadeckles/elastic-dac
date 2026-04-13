# =============================================================================
# Module: detection_rule — Variables
# =============================================================================
# These variables define the interface that every custom rule file must
# satisfy.  Required variables have no default; optional ones do.
# =============================================================================

# ---------------------------------------------------------------------------
# Required
# ---------------------------------------------------------------------------
variable "name" {
  description = "A human-readable name for the rule."
  type        = string
}

variable "description" {
  description = "The rule's description."
  type        = string
}

variable "type" {
  description = "Rule type: query, eql, esql, machine_learning, new_terms, saved_query, threat_match, threshold."
  type        = string
  validation {
    condition = contains([
      "query", "eql", "esql", "machine_learning",
      "new_terms", "saved_query", "threat_match", "threshold",
    ], var.type)
    error_message = "type must be one of: query, eql, esql, machine_learning, new_terms, saved_query, threat_match, threshold."
  }
}

variable "severity" {
  description = "Severity level: low, medium, high, critical."
  type        = string
  validation {
    condition     = contains(["low", "medium", "high", "critical"], var.severity)
    error_message = "severity must be one of: low, medium, high, critical."
  }
}

variable "risk_score" {
  description = "Numerical risk score (0–100)."
  type        = number
  validation {
    condition     = var.risk_score >= 0 && var.risk_score <= 100
    error_message = "risk_score must be between 0 and 100."
  }
}

variable "tags" {
  description = "Rule-specific tags.  Must include at least one 'Team: <name>' tag."
  type        = list(string)
}

variable "threat" {
  description = "MITRE ATT&CK threat mapping (full verbose format). Use mitre_attack instead for the simplified ID-only format."
  type        = list(any)
  default     = null
}

variable "mitre_attack" {
  description = <<-EOT
    Simplified MITRE ATT&CK mapping — just provide IDs, the module resolves
    names and references automatically.

    Example:
      mitre_attack = [
        { tactic = "TA0006", techniques = ["T1110"], subtechniques = ["T1110.001"] },
      ]
  EOT
  type = list(object({
    tactic        = string
    techniques    = optional(list(string), [])
    subtechniques = optional(list(string), [])
  }))
  default = null
}

# ---------------------------------------------------------------------------
# Optional — Query
# ---------------------------------------------------------------------------
variable "query" {
  description = "KQL / EQL / ES|QL query string."
  type        = string
  default     = null
}

variable "language" {
  description = "Query language: kuery, lucene, eql, esql."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Scheduling
# ---------------------------------------------------------------------------
variable "from" {
  description = "Relative start time for data analysis (e.g. now-6m)."
  type        = string
  default     = "now-6m"
}

variable "to" {
  description = "Relative end time for data analysis."
  type        = string
  default     = "now"
}

variable "interval" {
  description = "Rule execution interval (e.g. 5m)."
  type        = string
  default     = "5m"
}

# ---------------------------------------------------------------------------
# Optional — Behaviour
# ---------------------------------------------------------------------------
variable "enabled" {
  description = "Whether the rule is enabled."
  type        = bool
  default     = true
}

variable "max_signals" {
  description = "Max alerts per execution."
  type        = number
  default     = 100
}

# ---------------------------------------------------------------------------
# Optional — Metadata
# ---------------------------------------------------------------------------
variable "author" {
  description = "Rule author(s)."
  type        = list(string)
  default     = ["Detection Engineering"]
}

variable "default_tags" {
  description = "Tags appended to every rule (passed from root)."
  type        = list(string)
  default     = ["detection-as-code", "terraform-managed"]
}

variable "license" {
  description = "License string."
  type        = string
  default     = "Elastic License v2"
}

variable "references" {
  description = "External reference URLs."
  type        = list(string)
  default     = []
}

variable "false_positives" {
  description = "Known false-positive scenarios."
  type        = list(string)
  default     = []
}

variable "note" {
  description = "Investigation / triage notes (Markdown)."
  type        = string
  default     = null
}

variable "setup" {
  description = "Setup guide for prerequisites."
  type        = string
  default     = null
}

variable "rule_id" {
  description = "Stable UUID for the rule (auto-generated if omitted)."
  type        = string
  default     = null
}

variable "rule_version" {
  description = "Rule version number."
  type        = number
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Indices
# ---------------------------------------------------------------------------
variable "index" {
  description = "Index patterns the rule queries."
  type        = list(string)
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Space
# ---------------------------------------------------------------------------
variable "space_id" {
  description = "Kibana space ID."
  type        = string
  default     = "default"
}

# ---------------------------------------------------------------------------
# Optional — Building block
# ---------------------------------------------------------------------------
variable "building_block_type" {
  description = "Set to 'default' to mark as a building-block rule."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — New terms
# ---------------------------------------------------------------------------
variable "new_terms_fields" {
  description = "Fields for new_terms rule type."
  type        = list(string)
  default     = null
}

variable "history_window_start" {
  description = "History window start for new_terms rules."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Machine learning
# ---------------------------------------------------------------------------
variable "machine_learning_job_id" {
  description = "ML job ID(s) for machine_learning rules."
  type        = list(string)
  default     = null
}

variable "anomaly_threshold" {
  description = "Anomaly score threshold (0–100) for ML rules."
  type        = number
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Threat match
# ---------------------------------------------------------------------------
variable "threat_index" {
  description = "Threat intel index patterns."
  type        = list(string)
  default     = null
}

variable "threat_query" {
  description = "Threat intel filter query."
  type        = string
  default     = null
}

variable "threat_indicator_path" {
  description = "Path to indicator in threat documents."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Timestamp
# ---------------------------------------------------------------------------
variable "timestamp_override" {
  description = "Field name for timestamp override."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Timeline
# ---------------------------------------------------------------------------
variable "timeline_id" {
  description = "Timeline template ID."
  type        = string
  default     = null
}

variable "timeline_title" {
  description = "Timeline template title."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Optional — Exception lists
# ---------------------------------------------------------------------------
variable "exceptions_list" {
  description = "Exception list references to attach to this rule."
  type = list(object({
    id             = string
    list_id        = string
    namespace_type = string
    type           = string
  }))
  default = []
}

# ---------------------------------------------------------------------------
# Optional — Threshold
# ---------------------------------------------------------------------------
variable "threshold" {
  description = "Threshold configuration for threshold-type rules."
  type = object({
    value = number
    field = optional(list(string))
  })
  default = null
}

# ---------------------------------------------------------------------------
# Optional — Alert suppression
# ---------------------------------------------------------------------------
variable "alert_suppression" {
  description = "Alert suppression configuration."
  type = object({
    group_by                = list(string)
    duration                = optional(string)
    missing_fields_strategy = optional(string)
  })
  default = null
}
