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
  # Default is local for laptop development. To enable the AWS S3 +
  # DynamoDB-locked remote state used by the GitLab pipeline:
  #
  #   cp backend.tf.example backend.tf
  #
  # Backend values (bucket, key, region, lock table) are injected at
  # init time by the pipeline via -backend-config flags. See:
  #   ../.gitlab/GITLAB_RUNNERS.md   for the AWS provisioning steps
  #   ../.gitlab-ci.yml               for the .terraform-init snippet
  # -----------------------------------------------------------
}

# =============================================================================
# Provider Configuration
# =============================================================================
# Credentials come from variables (CI/CD) or from a .env / terraform.tfvars
# file for local development.  The provider also honours environment variables
# ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD, ELASTICSEARCH_ENDPOINTS,
# KIBANA_USERNAME, KIBANA_PASSWORD, KIBANA_ENDPOINT.
# =============================================================================
provider "elasticstack" {
  elasticsearch {
    username  = var.elasticsearch_username
    password  = var.elasticsearch_password
    endpoints = var.elasticsearch_endpoints
  }

  kibana {
    username  = var.kibana_username
    password  = var.kibana_password
    endpoints = [var.kibana_endpoint]
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
