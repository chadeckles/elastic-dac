# =============================================================================
# Suspicious PowerShell Encoded Command Execution
# =============================================================================
# Detects PowerShell with -EncodedCommand / -enc flags — a common
# obfuscation technique used by attackers.
#
# MITRE ATT&CK:  TA0002 Execution → T1059.001 PowerShell
#                TA0005 Defense Evasion → T1027 Obfuscated Files
# Team:          Threat Intel
# =============================================================================

module "suspicious_powershell_encoded" {
  source = "../modules/detection_rule"

  name        = "Suspicious PowerShell Encoded Command Execution"
  description = "Detects execution of PowerShell with encoded commands, often used by attackers to obfuscate malicious payloads."
  type        = "query"
  severity    = "high"
  risk_score  = 80

  query    = "process.name:\"powershell.exe\" AND process.command_line:(*-enc* OR *-EncodedCommand* OR *-e *)"
  language = "kuery"

  index = [
    "winlogbeat-*",
    "logs-endpoint.events.*",
    "logs-windows.*",
  ]

  tags = [
    "windows",
    "powershell",
    "execution",
    "defense-evasion",
    "Team: Threat Intel",
  ]

  false_positives = [
    "Legitimate encoded scripts used by IT automation",
    "SCCM or Intune deployment scripts",
  ]

  references = [
    "https://attack.mitre.org/techniques/T1059/001/",
    "https://attack.mitre.org/techniques/T1027/",
  ]

  note = <<-EOT
    ## Triage Steps
    1. Decode the Base64 encoded command.
    2. Examine the parent process tree.
    3. Check for network connections during / after execution.
    4. Review file-system artefacts created by the process.
  EOT

  threat = [
    {
      tactic = {
        id        = "TA0002"
        name      = "Execution"
        reference = "https://attack.mitre.org/tactics/TA0002/"
      }
      technique = [
        {
          id        = "T1059"
          name      = "Command and Scripting Interpreter"
          reference = "https://attack.mitre.org/techniques/T1059/"
          subtechnique = [
            {
              id        = "T1059.001"
              name      = "PowerShell"
              reference = "https://attack.mitre.org/techniques/T1059/001/"
            }
          ]
        }
      ]
    },
    {
      tactic = {
        id        = "TA0005"
        name      = "Defense Evasion"
        reference = "https://attack.mitre.org/tactics/TA0005/"
      }
      technique = [
        {
          id        = "T1027"
          name      = "Obfuscated Files or Information"
          reference = "https://attack.mitre.org/techniques/T1027/"
          subtechnique = []
        }
      ]
    }
  ]

  # ---- Toggle (inherit directory default or override per-rule) --------
  enabled = var.default_enabled     # ← set to true/false to override

  space_id     = var.space_id
  default_tags = var.default_tags
}
