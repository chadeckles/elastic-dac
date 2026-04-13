# =============================================================================
# Suspicious Cron Job Created
# =============================================================================
# Alerts when a non-root user creates a cron job, which may indicate an
# attacker establishing persistence.
#
# MITRE ATT&CK:  TA0003 Persistence → T1053.003 Cron
# Team:          CSSP
# =============================================================================

module "suspicious_cron_creation" {
  source = "../modules/detection_rule"

  name        = "Suspicious Cron Job Created"
  description = "Detects creation of cron jobs by non-root users, which may indicate persistence mechanisms."
  type        = "query"
  severity    = "medium"
  risk_score  = 50

  query    = "event.category:process AND process.name:(crontab OR at) AND NOT user.name:root"
  language = "kuery"

  index = [
    "logs-endpoint.events.*",
    "auditbeat-*",
    "logs-*",
  ]

  tags = [
    "linux",
    "persistence",
    "cron",
    "Team: CSSP",
  ]

  false_positives = [
    "Developers creating scheduled tasks for legitimate purposes",
  ]

  references = [
    "https://attack.mitre.org/techniques/T1053/003/",
  ]

  mitre_attack = [
    { tactic = "TA0003", techniques = ["T1053"], subtechniques = ["T1053.003"] },
  ]

  # ---- Toggle (inherit directory default or override per-rule) --------
  enabled = var.default_enabled     # ← set to true/false to override

  space_id     = var.space_id
  default_tags = var.default_tags
}
