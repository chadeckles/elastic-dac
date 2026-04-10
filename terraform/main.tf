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
  # Backend — default is local; switch to remote for team use.
  # Uncomment the block below for an S3 or similar backend.
  # -----------------------------------------------------------
  # backend "s3" {
  #   bucket         = "my-tf-state-detection-as-code"
  #   key            = "elastic/detection-rules/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
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
module "exceptions" {
  source = "./exceptions"

  space_id = var.kibana_space_id
}
