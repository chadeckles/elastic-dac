# =============================================================================
# Module: detection_rule  (single rule)
# =============================================================================
# Creates ONE Elastic Security detection rule with standards enforcement.
# Used by individual rule files in terraform/custom_rules/ to guarantee
# consistent structure, required tags, and MITRE mapping.
#
# Reference:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_detection_rule
# =============================================================================

terraform {
  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "~> 0.12"
    }
  }
}

resource "elasticstack_kibana_security_detection_rule" "this" {
  # ---- Required -----------------------------------------------------------
  name        = var.name
  description = var.description
  type        = var.type

  # ---- Query / Language ---------------------------------------------------
  query    = var.query
  language = var.language

  # ---- Scheduling ---------------------------------------------------------
  from     = var.from
  to       = var.to
  interval = var.interval

  # ---- Severity & Risk ----------------------------------------------------
  severity   = var.severity
  risk_score = var.risk_score

  # ---- Toggle -------------------------------------------------------------
  enabled = var.enabled

  # ---- Metadata -----------------------------------------------------------
  author          = var.author
  tags            = distinct(concat(var.default_tags, var.tags))
  license         = var.license
  references      = var.references
  false_positives = var.false_positives
  note            = var.note
  setup           = var.setup
  rule_id         = var.rule_id
  version         = var.rule_version
  max_signals     = var.max_signals

  # ---- Indices ------------------------------------------------------------
  index = var.index

  # ---- Space --------------------------------------------------------------
  space_id = var.space_id

  # ---- Building block -----------------------------------------------------
  building_block_type = var.building_block_type

  # ---- New terms ----------------------------------------------------------
  new_terms_fields     = var.new_terms_fields
  history_window_start = var.history_window_start

  # ---- Machine learning ---------------------------------------------------
  machine_learning_job_id = var.machine_learning_job_id
  anomaly_threshold       = var.anomaly_threshold

  # ---- Threat match -------------------------------------------------------
  threat_index          = var.threat_index
  threat_query          = var.threat_query
  threat_indicator_path = var.threat_indicator_path

  # ---- Timestamp ----------------------------------------------------------
  timestamp_override = var.timestamp_override

  # ---- Timeline -----------------------------------------------------------
  timeline_id    = var.timeline_id
  timeline_title = var.timeline_title

  # ---- MITRE ATT&CK threat mapping ----------------------------------------
  # NOTE: threat, exceptions_list, threshold, alert_suppression are nested
  # attributes in the elasticstack provider (Terraform Framework), NOT block
  # types — so they must use attribute assignment, not dynamic blocks.
  threat = [for t in var.threat : {
    framework = "MITRE ATT&CK"
    tactic = {
      id        = t.tactic.id
      name      = t.tactic.name
      reference = t.tactic.reference
    }
    technique = try(length(t.technique) > 0 ? [for tech in t.technique : {
      id        = tech.id
      name      = tech.name
      reference = tech.reference
      # Provider returns null (not []) when no subtechniques — match that
      subtechnique = try(length(tech.subtechnique) > 0 ? [for sub in tech.subtechnique : {
        id        = sub.id
        name      = sub.name
        reference = sub.reference
      }] : null, null)
    }] : null, null)
  }]

  # ---- Exception list references -------------------------------------------
  exceptions_list = length(var.exceptions_list) > 0 ? var.exceptions_list : null

  # ---- Threshold -----------------------------------------------------------
  threshold = var.threshold

  # ---- Alert suppression ---------------------------------------------------
  alert_suppression = var.alert_suppression
}
