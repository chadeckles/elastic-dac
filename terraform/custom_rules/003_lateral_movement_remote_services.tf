# =============================================================================
# Lateral Movement via Remote Service Creation
# =============================================================================
# EQL sequence rule: successful remote auth followed by sc.exe service
# creation within 1 minute on the same host.
#
# MITRE ATT&CK:  TA0008 Lateral Movement → T1021 Remote Services
# Team:          CSSP
# =============================================================================

module "lateral_movement_remote_services" {
  source = "../modules/detection_rule"

  name        = "Lateral Movement via Remote Service Creation"
  description = "Detects remote creation of Windows services, a common lateral movement technique."
  type        = "eql"
  severity    = "critical"
  risk_score  = 90

  query = <<-EOQ
    sequence by host.id with maxspan=1m
      [authentication where event.outcome == "success" and source.ip != null]
      [process where event.type == "start" and process.name == "sc.exe" and process.args : "create"]
  EOQ

  language = "eql"
  from     = "now-10m"

  index = [
    "winlogbeat-*",
    "logs-endpoint.events.*",
    "logs-windows.*",
  ]

  tags = [
    "windows",
    "lateral-movement",
    "persistence",
    "Team: CSSP",
  ]

  false_positives = [
    "Legitimate remote administration by IT staff",
  ]

  references = [
    "https://attack.mitre.org/techniques/T1021/",
    "https://attack.mitre.org/techniques/T1543/003/",
  ]

  mitre_attack = [
    { tactic = "TA0008", techniques = ["T1021"], subtechniques = [] },
  ]

  # ---- Toggle (inherit directory default or override per-rule) --------
  enabled = var.default_enabled     # ← set to true/false to override

  space_id     = var.space_id
  default_tags = var.default_tags
}
