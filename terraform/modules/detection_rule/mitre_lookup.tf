# =============================================================================
# MITRE ATT&CK Lookup Maps
# =============================================================================
# Auto-resolves tactic/technique/subtechnique IDs to their display names
# and reference URLs.  Engineers only need to provide IDs — the module fills
# in the rest.
#
# Usage in a rule file (simplified):
#
#   mitre_attack = [
#     {
#       tactic     = "TA0006"
#       techniques = ["T1110"]
#       subtechniques = ["T1110.001"]
#     }
#   ]
#
# The module builds the full threat block automatically.
# =============================================================================

locals {
  # ---- Tactics ------------------------------------------------------------
  mitre_tactics = {
    TA0001 = { name = "Initial Access",       reference = "https://attack.mitre.org/tactics/TA0001/" }
    TA0002 = { name = "Execution",            reference = "https://attack.mitre.org/tactics/TA0002/" }
    TA0003 = { name = "Persistence",          reference = "https://attack.mitre.org/tactics/TA0003/" }
    TA0004 = { name = "Privilege Escalation",  reference = "https://attack.mitre.org/tactics/TA0004/" }
    TA0005 = { name = "Defense Evasion",       reference = "https://attack.mitre.org/tactics/TA0005/" }
    TA0006 = { name = "Credential Access",     reference = "https://attack.mitre.org/tactics/TA0006/" }
    TA0007 = { name = "Discovery",             reference = "https://attack.mitre.org/tactics/TA0007/" }
    TA0008 = { name = "Lateral Movement",      reference = "https://attack.mitre.org/tactics/TA0008/" }
    TA0009 = { name = "Collection",            reference = "https://attack.mitre.org/tactics/TA0009/" }
    TA0010 = { name = "Exfiltration",          reference = "https://attack.mitre.org/tactics/TA0010/" }
    TA0011 = { name = "Command and Control",   reference = "https://attack.mitre.org/tactics/TA0011/" }
    TA0040 = { name = "Impact",                reference = "https://attack.mitre.org/tactics/TA0040/" }
    TA0042 = { name = "Resource Development",  reference = "https://attack.mitre.org/tactics/TA0042/" }
    TA0043 = { name = "Reconnaissance",        reference = "https://attack.mitre.org/tactics/TA0043/" }
  }

  # ---- Techniques ---------------------------------------------------------
  # Coverage: techniques used in the 5 baseline rules + commonly needed ones.
  # Add more as needed — the pattern is always ID → {name, reference}.
  mitre_techniques = {
    T1021  = { name = "Remote Services",                          reference = "https://attack.mitre.org/techniques/T1021/" }
    T1027  = { name = "Obfuscated Files or Information",          reference = "https://attack.mitre.org/techniques/T1027/" }
    T1048  = { name = "Exfiltration Over Alternative Protocol",   reference = "https://attack.mitre.org/techniques/T1048/" }
    T1053  = { name = "Scheduled Task/Job",                       reference = "https://attack.mitre.org/techniques/T1053/" }
    T1059  = { name = "Command and Scripting Interpreter",        reference = "https://attack.mitre.org/techniques/T1059/" }
    T1071  = { name = "Application Layer Protocol",               reference = "https://attack.mitre.org/techniques/T1071/" }
    T1078  = { name = "Valid Accounts",                           reference = "https://attack.mitre.org/techniques/T1078/" }
    T1110  = { name = "Brute Force",                              reference = "https://attack.mitre.org/techniques/T1110/" }
    T1190  = { name = "Exploit Public-Facing Application",        reference = "https://attack.mitre.org/techniques/T1190/" }
    T1543  = { name = "Create or Modify System Process",          reference = "https://attack.mitre.org/techniques/T1543/" }
    T1566  = { name = "Phishing",                                 reference = "https://attack.mitre.org/techniques/T1566/" }
    T1068  = { name = "Exploitation for Privilege Escalation",    reference = "https://attack.mitre.org/techniques/T1068/" }
    T1055  = { name = "Process Injection",                        reference = "https://attack.mitre.org/techniques/T1055/" }
    T1003  = { name = "OS Credential Dumping",                    reference = "https://attack.mitre.org/techniques/T1003/" }
    T1518  = { name = "Software Discovery",                       reference = "https://attack.mitre.org/techniques/T1518/" }
    T1105  = { name = "Ingress Tool Transfer",                    reference = "https://attack.mitre.org/techniques/T1105/" }
    T1486  = { name = "Data Encrypted for Impact",                reference = "https://attack.mitre.org/techniques/T1486/" }
    T1595  = { name = "Active Scanning",                          reference = "https://attack.mitre.org/techniques/T1595/" }
    T1592  = { name = "Gather Victim Host Information",           reference = "https://attack.mitre.org/techniques/T1592/" }
  }

  # ---- Subtechniques ------------------------------------------------------
  mitre_subtechniques = {
    "T1021.001" = { name = "Remote Desktop Protocol",                              reference = "https://attack.mitre.org/techniques/T1021/001/" }
    "T1021.002" = { name = "SMB/Windows Admin Shares",                             reference = "https://attack.mitre.org/techniques/T1021/002/" }
    "T1048.001" = { name = "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", reference = "https://attack.mitre.org/techniques/T1048/001/" }
    "T1053.003" = { name = "Cron",                                                  reference = "https://attack.mitre.org/techniques/T1053/003/" }
    "T1053.005" = { name = "Scheduled Task",                                        reference = "https://attack.mitre.org/techniques/T1053/005/" }
    "T1059.001" = { name = "PowerShell",                                            reference = "https://attack.mitre.org/techniques/T1059/001/" }
    "T1059.003" = { name = "Windows Command Shell",                                 reference = "https://attack.mitre.org/techniques/T1059/003/" }
    "T1059.004" = { name = "Unix Shell",                                            reference = "https://attack.mitre.org/techniques/T1059/004/" }
    "T1078.001" = { name = "Default Accounts",                                      reference = "https://attack.mitre.org/techniques/T1078/001/" }
    "T1078.002" = { name = "Domain Accounts",                                       reference = "https://attack.mitre.org/techniques/T1078/002/" }
    "T1078.003" = { name = "Local Accounts",                                        reference = "https://attack.mitre.org/techniques/T1078/003/" }
    "T1078.004" = { name = "Cloud Accounts",                                        reference = "https://attack.mitre.org/techniques/T1078/004/" }
    "T1110.001" = { name = "Password Guessing",                                     reference = "https://attack.mitre.org/techniques/T1110/001/" }
    "T1110.003" = { name = "Password Spraying",                                     reference = "https://attack.mitre.org/techniques/T1110/003/" }
    "T1543.003" = { name = "Windows Service",                                       reference = "https://attack.mitre.org/techniques/T1543/003/" }
    "T1566.001" = { name = "Spearphishing Attachment",                              reference = "https://attack.mitre.org/techniques/T1566/001/" }
    "T1566.002" = { name = "Spearphishing Link",                                    reference = "https://attack.mitre.org/techniques/T1566/002/" }
    "T1003.001" = { name = "LSASS Memory",                                          reference = "https://attack.mitre.org/techniques/T1003/001/" }
  }

  # ---- Build the full threat list from simplified mitre_attack input ------
  resolved_threat = var.mitre_attack != null ? [
    for entry in var.mitre_attack : {
      tactic = {
        id        = entry.tactic
        name      = local.mitre_tactics[entry.tactic].name
        reference = local.mitre_tactics[entry.tactic].reference
      }
      technique = [
        for tid in coalesce(entry.techniques, []) : {
          id        = tid
          name      = local.mitre_techniques[tid].name
          reference = local.mitre_techniques[tid].reference
          subtechnique = [
            for sid in coalesce(entry.subtechniques, []) :
            {
              id        = sid
              name      = local.mitre_subtechniques[sid].name
              reference = local.mitre_subtechniques[sid].reference
            }
            if startswith(sid, "${tid}.")
          ]
        }
      ]
    }
  ] : null
}
