# =============================================================================
# Detection as Code — Terraform Root Configuration
# =============================================================================
# This is the root module that wires together the elasticstack provider,
# Elastic's prebuilt detection rules, custom detection rules, and
# exception lists / items.
#
# Reference:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "~> 0.12"
    }
  }

  # -----------------------------------------------------------
  # Backend
  #
  # S3 remote state with native S3 locking (Terraform 1.10+).
  # All values (bucket, key, region) are injected at init time by the
  # GitLab pipeline's `-backend-config` flags — this block is intentionally
  # empty. See:
  #   ../.gitlab/GITLAB_RUNNERS.md   for the AWS provisioning steps
  #   ../.gitlab-ci.yml              for the .terraform-init snippet
  #
  # For laptop dev without S3, comment out the backend block below and
  # Terraform will fall back to local state in terraform.tfstate.
  # -----------------------------------------------------------
  backend "s3" {}
}

# =============================================================================
# Provider Configuration
# =============================================================================
# Authentication is API-key only and Kibana-only — every resource this repo
# manages (detection rules, exception lists, exception items, prebuilt-rule
# install) is a Kibana resource, so we don't configure the elasticsearch{}
# block. If you ever add an Elasticsearch resource (index template, ILM
# policy, transform, etc.) re-introduce the block + ELASTICSEARCH_API_KEY /
# ELASTICSEARCH_ENDPOINTS env vars.
#
# Credentials come from GitLab CI/CD variables (KIBANA_API_KEY,
# KIBANA_ENDPOINT) which the elasticstack provider reads automatically as
# env vars.
# =============================================================================
provider "elasticstack" {
  kibana {
    api_key   = var.kibana_api_key
    endpoints = var.kibana_endpoint != null ? [var.kibana_endpoint] : null
  }
}

# =============================================================================
# Child Modules
# =============================================================================

# Custom detection rules — each rule is its own .tf file in custom_rules/
module "custom_rules" {
  source = "./custom_rules"

  space_id        = var.kibana_space_id
  default_tags    = var.default_rule_tags
  default_enabled = var.default_enabled
}

# Exception lists — each list is its own .tf file in exceptions/
# These are SHARED lists referenced by multiple rules.
module "exceptions" {
  source = "./exceptions"

  space_id = var.kibana_space_id
}

# Rule-scoped exception items — each .tf file holds analyst tuning for ONE rule.
# Uses the elasticstack_kibana_security_exception_item resource directly,
# attached to the rule's auto-created rule-default list. This is the
# pattern Elastic Security uses by default in production deployments.
module "rule_exceptions" {
  source = "./rule_exceptions"

  space_id           = var.kibana_space_id
  rule_default_lists = module.custom_rules.rule_default_exception_list_ids
}
