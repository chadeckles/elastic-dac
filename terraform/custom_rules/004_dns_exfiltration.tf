# =============================================================================
# Potential Data Exfiltration over DNS
# =============================================================================
# Flags DNS queries with unusually long names (>50 chars) that may indicate
# DNS tunneling.
#
# MITRE ATT&CK:  TA0010 Exfiltration → T1048 Alt Protocol
# Team:          SOC
# =============================================================================

module "dns_exfiltration" {
  source = "../modules/detection_rule"

  name        = "Potential Data Exfiltration over DNS"
  description = "Detects unusually long DNS queries that may indicate DNS tunneling for data exfiltration."
  type        = "query"
  severity    = "medium"
  risk_score  = 60

  query    = "dns.question.name:* AND length(dns.question.name) > 50"
  language = "kuery"

  index = [
    "packetbeat-*",
    "logs-*",
    "filebeat-*",
  ]

  tags = [
    "dns",
    "exfiltration",
    "network",
    "Team: SOC",
  ]

  false_positives = [
    "CDN domains with long subdomains",
    "Legitimate SaaS applications",
  ]

  references = [
    "https://attack.mitre.org/techniques/T1048/",
    "https://attack.mitre.org/techniques/T1071/004/",
  ]

  threat = [
    {
      tactic = {
        id        = "TA0010"
        name      = "Exfiltration"
        reference = "https://attack.mitre.org/tactics/TA0010/"
      }
      technique = [
        {
          id        = "T1048"
          name      = "Exfiltration Over Alternative Protocol"
          reference = "https://attack.mitre.org/techniques/T1048/"
          subtechnique = [
            {
              id        = "T1048.001"
              name      = "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"
              reference = "https://attack.mitre.org/techniques/T1048/001/"
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
