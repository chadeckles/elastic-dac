# =============================================================================
# Trusted Internal Infrastructure — Exception List
# =============================================================================
# Suppresses false-positive authentication alerts from known-good
# infrastructure: load-balancer health checks, monitoring accounts, etc.
# =============================================================================

module "trusted_infrastructure" {
  source = "../modules/exception_list"

  list_id     = "trusted-infrastructure"
  name        = "Trusted Internal Infrastructure"
  description = "Exceptions for known-good internal infrastructure that triggers false positives."
  type        = "detection"
  tags        = ["infrastructure", "false-positive-reduction"]

  items = [
    {
      item_id     = "lb-health-check"
      name        = "Load Balancer Health Checks"
      description = "Health-check probes from internal load balancers generate repeated auth failures."
      tags        = ["load-balancer"]
      entries = [
        {
          field    = "source.ip"
          type     = "match"
          operator = "included"
          value    = "10.0.0.1"
        }
      ]
    },
    {
      item_id     = "monitoring-svc"
      name        = "Monitoring Service Account"
      description = "The monitoring service account authenticates frequently across all hosts."
      tags        = ["service-account"]
      entries = [
        {
          field    = "user.name"
          type     = "match"
          operator = "included"
          value    = "svc_monitoring"
        }
      ]
    },
        {
      item_id     = "nat-gateway"
      name        = "NAT Gateway"
      description = "NAT gateway generates auth noise from outbound traffic."
      tags        = ["network"]
      entries = [
        {
          field    = "source.ip"
          type     = "match"
          operator = "included"
          value    = "10.0.1.1"
        }
      ]
    },
  ]

  space_id = var.space_id
}
