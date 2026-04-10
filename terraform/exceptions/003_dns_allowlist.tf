# =============================================================================
# DNS Allowlist — Exception List
# =============================================================================
# Suppresses DNS-tunneling false positives from known CDN / SaaS domains
# that naturally produce long subdomain names.
# =============================================================================

module "dns_allowlist" {
  source = "../modules/exception_list"

  list_id     = "dns-allowlist"
  name        = "DNS Allowlist"
  description = "Known long-domain patterns that are benign (CDN, SaaS)."
  type        = "detection"
  tags        = ["dns", "allowlist"]

  items = [
    {
      item_id     = "cdn-domains"
      name        = "CDN Long Subdomain Patterns"
      description = "Content-delivery networks use long hashed subdomains."
      tags        = ["cdn"]
      entries = [
        {
          field    = "dns.question.name"
          type     = "wildcard"
          operator = "included"
          value    = "*.cloudfront.net"
        }
      ]
    },
    {
      item_id     = "saas-domains"
      name        = "SaaS Application Domains"
      description = "SaaS applications with long auto-generated subdomains."
      tags        = ["saas"]
      entries = [
        {
          field    = "dns.question.name"
          type     = "wildcard"
          operator = "included"
          value    = "*.azurewebsites.net"
        }
      ]
    },
  ]

  space_id = var.space_id
}
