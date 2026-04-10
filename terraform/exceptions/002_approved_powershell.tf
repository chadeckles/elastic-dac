# =============================================================================
# Approved PowerShell Automation — Exception List
# =============================================================================
# Suppresses encoded-PowerShell alerts for sanctioned management tools.
# =============================================================================

module "approved_powershell" {
  source = "../modules/exception_list"

  list_id     = "approved-powershell-automation"
  name        = "Approved PowerShell Automation"
  description = "Exceptions for encoded PowerShell usage by sanctioned automation tools."
  type        = "detection"
  tags        = ["powershell", "automation", "false-positive-reduction"]

  items = [
    {
      item_id     = "sccm-client"
      name        = "SCCM Client Scripts"
      description = "System Center Configuration Manager uses encoded PowerShell for deployment scripts."
      tags        = ["sccm"]
      entries = [
        {
          field    = "process.parent.name"
          type     = "match"
          operator = "included"
          value    = "CcmExec.exe"
        }
      ]
    },
    {
      item_id     = "intune-management"
      name        = "Intune Management Extension"
      description = "Microsoft Intune management extension uses encoded PowerShell for policy enforcement."
      tags        = ["intune"]
      entries = [
        {
          field    = "process.parent.name"
          type     = "match"
          operator = "included"
          value    = "AgentExecutor.exe"
        },
        {
          field    = "user.name"
          type     = "match"
          operator = "included"
          value    = "SYSTEM"
        }
      ]
    },
  ]

  space_id = var.space_id
}
