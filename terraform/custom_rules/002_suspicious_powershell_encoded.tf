# =============================================================================
# Suspicious PowerShell Encoded Command Execution
# =============================================================================
# Detects PowerShell with -EncodedCommand / -enc flags — a common
# obfuscation technique used by attackers.
#
# MITRE ATT&CK:  TA0002 Execution → T1059.001 PowerShell
#                TA0005 Defense Evasion → T1027 Obfuscated Files
# Team:          CSSP
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
    "Team: CSSP",
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

  mitre_attack = [
    { tactic = "TA0002", techniques = ["T1059"], subtechniques = ["T1059.001"] },
    { tactic = "TA0005", techniques = ["T1027"], subtechniques = [] },
  ]

  # ---- Toggle (inherit directory default or override per-rule) --------
  enabled = var.default_enabled     # ← set to true/false to override

  space_id     = var.space_id
  default_tags = var.default_tags
}
