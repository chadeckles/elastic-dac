# =============================================================================
# custom_rules — Provider passthrough
# =============================================================================
# Child modules inherit providers from their caller, but we declare the
# requirement here so `terraform validate` works on this directory in
# isolation and so IDE tooling resolves resource types correctly.
# =============================================================================

terraform {
  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "~> 0.12"
    }
  }
}
