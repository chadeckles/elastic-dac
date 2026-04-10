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
  dynamic "threat" {
    for_each = var.threat
    content {
      framework = "MITRE ATT&CK"

      tactic {
        id        = threat.value.tactic.id
        name      = threat.value.tactic.name
        reference = threat.value.tactic.reference
      }

      dynamic "technique" {
        for_each = lookup(threat.value, "technique", [])
        content {
          id        = technique.value.id
          name      = technique.value.name
          reference = technique.value.reference

          dynamic "subtechnique" {
            for_each = lookup(technique.value, "subtechnique", [])
            content {
              id        = subtechnique.value.id
              name      = subtechnique.value.name
              reference = subtechnique.value.reference
            }
          }
        }
      }
    }
  }

  # ---- Exception list references -------------------------------------------
  dynamic "exceptions_list" {
    for_each = var.exceptions_list
    content {
      id             = exceptions_list.value.id
      list_id        = exceptions_list.value.list_id
      namespace_type = exceptions_list.value.namespace_type
      type           = exceptions_list.value.type
    }
  }

  # ---- Threshold -----------------------------------------------------------
  dynamic "threshold" {
    for_each = var.threshold != null ? [var.threshold] : []
    content {
      value = threshold.value.value
      field = lookup(threshold.value, "field", null)
    }
  }

  # ---- Alert suppression ---------------------------------------------------
  dynamic "alert_suppression" {
    for_each = var.alert_suppression != null ? [var.alert_suppression] : []
    content {
      group_by                = alert_suppression.value.group_by
      duration                = lookup(alert_suppression.value, "duration", null)
      missing_fields_strategy = lookup(alert_suppression.value, "missing_fields_strategy", null)
    }
  }
}
