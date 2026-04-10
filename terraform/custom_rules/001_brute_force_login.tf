# =============================================================================
# Brute-Force Login Attempts
# =============================================================================
# Detects >10 failed login attempts from a single source within 5 minutes.
#
# MITRE ATT&CK:  TA0006 Credential Access → T1110 Brute Force
# Team:          SOC
# =============================================================================

module "brute_force_login" {
  source = "../modules/detection_rule"

  name        = "Brute-Force Login Attempts"
  description = "Detects more than 10 failed login attempts from a single source within 5 minutes, indicating a potential brute-force attack."
  type        = "threshold"
  severity    = "high"
  risk_score  = 73

  query    = "event.category:authentication AND event.outcome:failure"
  language = "kuery"
  from     = "now-5m"
  interval = "5m"

  index = [
    "logs-*",
    "filebeat-*",
    "winlogbeat-*",
  ]

  tags = [
    "brute-force",
    "authentication",
    "credential-access",
    "Team: SOC",
  ]

  false_positives = [
    "Automated vulnerability scanners",
    "Misconfigured service accounts",
  ]

  references = [
    "https://attack.mitre.org/techniques/T1110/",
  ]

  note = <<-EOT
    ## Triage Steps
    1. Identify the source IP and geo-location.
    2. Check if the targeted account is a service account.
    3. Correlate with successful logins from the same source.
    4. Verify if the source IP is in a known threat feed.
  EOT

  setup = <<-EOT
    ## Prerequisites
    - Authentication logs must be collected (e.g., Elastic Agent, Winlogbeat).
    - Ensure `event.category` and `event.outcome` fields are populated.
  EOT

  threshold = {
    field = ["source.ip"]
    value = 10
  }

  threat = [
    {
      tactic = {
        id        = "TA0006"
        name      = "Credential Access"
        reference = "https://attack.mitre.org/tactics/TA0006/"
      }
      technique = [
        {
          id        = "T1110"
          name      = "Brute Force"
          reference = "https://attack.mitre.org/techniques/T1110/"
          subtechnique = [
            {
              id        = "T1110.001"
              name      = "Password Guessing"
              reference = "https://attack.mitre.org/techniques/T1110/001/"
            }
          ]
        }
      ]
    }
  ]

  # ---- Toggle (inherit directory default or override per-rule) --------
  enabled = var.default_enabled     # ← set to true/false to override

  space_id     = var.space_id
  default_tags = var.default_tags
}
