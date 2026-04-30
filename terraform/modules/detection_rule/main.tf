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
  # Supports two input modes:
  #   1. mitre_attack = [{tactic = "TA0006", techniques = ["T1110"], ...}]
  #      → IDs only, module resolves names/URLs from mitre_lookup.tf
  #   2. threat = [{tactic = {id = ..., name = ..., reference = ...}, ...}]
  #      → Full verbose format (legacy / imported rules)
  #
  # If mitre_attack is provided, it takes precedence over threat.
  threat = local.resolved_threat != null ? [
    for t in local.resolved_threat : {
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
        subtechnique = try(length(tech.subtechnique) > 0 ? [for sub in tech.subtechnique : {
          id        = sub.id
          name      = sub.name
          reference = sub.reference
        }] : null, null)
      }] : null, null)
    }
    ] : var.threat != null ? [for t in var.threat : {
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
        subtechnique = try(length(tech.subtechnique) > 0 ? [for sub in tech.subtechnique : {
          id        = sub.id
          name      = sub.name
          reference = sub.reference
        }] : null, null)
      }] : null, null)
  }] : []

  # ---- Exception list references -------------------------------------------
  # Combines:
  #   1. Shared exception lists supplied via var.exceptions_list
  #   2. The auto-generated rule-default exception list (if rule_exceptions
  #      were provided), which contains this rule's narrow exception items.
  exceptions_list = length(local.all_exception_list_refs) > 0 ? local.all_exception_list_refs : null

  # ---- Threshold -----------------------------------------------------------
  threshold = var.threshold

  # ---- Alert suppression ---------------------------------------------------
  alert_suppression = var.alert_suppression
}

# ---------------------------------------------------------------------------
# Rule-default exception list + items (inline per-rule exceptions)
# ---------------------------------------------------------------------------
# Created only when var.rule_exceptions is non-empty. Mirrors the way the
# Kibana Rules UI manages "rule-default" exception items: a small list scoped
# to a single rule, holding analyst-tuned suppressions.
#
# Reference:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item
# ---------------------------------------------------------------------------
locals {
  has_rule_exceptions = length(var.rule_exceptions) > 0

  rule_exception_list_id = coalesce(
    var.rule_exception_list_id,
    format(
      "%s-exceptions",
      replace(replace(lower(var.name), "/[^a-z0-9]+/", "-"), "/(^-+|-+$)/", "")
    )
  )

  rule_default_list_ref = local.has_rule_exceptions ? [{
    id             = elasticstack_kibana_security_exception_list.rule_default[0].id
    list_id        = elasticstack_kibana_security_exception_list.rule_default[0].list_id
    namespace_type = elasticstack_kibana_security_exception_list.rule_default[0].namespace_type
    type           = elasticstack_kibana_security_exception_list.rule_default[0].type
  }] : []

  all_exception_list_refs = concat(var.exceptions_list, local.rule_default_list_ref)
}

resource "elasticstack_kibana_security_exception_list" "rule_default" {
  count = local.has_rule_exceptions ? 1 : 0

  list_id        = local.rule_exception_list_id
  name           = format("%s — Exceptions", var.name)
  description    = format("Rule-scoped exception items for: %s", var.name)
  type           = "detection"
  namespace_type = "single"
  tags           = ["rule-default", "terraform-managed"]
  space_id       = var.space_id
}

resource "elasticstack_kibana_security_exception_item" "rule_default" {
  for_each = {
    for item in var.rule_exceptions : item.item_id => item
    if local.has_rule_exceptions
  }

  list_id        = elasticstack_kibana_security_exception_list.rule_default[0].list_id
  item_id        = each.value.item_id
  name           = each.value.name
  description    = each.value.description
  type           = lookup(each.value, "type", "simple")
  namespace_type = "single"
  os_types       = lookup(each.value, "os_types", null)
  tags           = lookup(each.value, "tags", [])
  expire_time    = lookup(each.value, "expire_time", null)
  space_id       = var.space_id

  entries = [for e in each.value.entries : {
    field    = e.field
    type     = e.type
    operator = try(e.operator, "included")
    value    = try(e.value, null)
    values   = try(e.values, null)
  }]
}
