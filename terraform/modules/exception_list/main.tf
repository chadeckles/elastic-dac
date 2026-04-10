# =============================================================================
# Module: exception_list  (single list + items)
# =============================================================================
# Creates ONE exception list container and its child exception items.
#
# References:
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_list
#   https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item
# =============================================================================

terraform {
  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "~> 0.12"
    }
  }
}

# ---------------------------------------------------------------------------
# Exception List container
# ---------------------------------------------------------------------------
resource "elasticstack_kibana_security_exception_list" "this" {
  list_id        = var.list_id
  name           = var.name
  description    = var.description
  type           = var.type
  namespace_type = var.namespace_type
  os_types       = var.os_types
  tags           = var.tags
  space_id       = var.space_id
}

# ---------------------------------------------------------------------------
# Exception Items
# ---------------------------------------------------------------------------
resource "elasticstack_kibana_security_exception_item" "this" {
  for_each = { for item in var.items : item.item_id => item }

  list_id        = elasticstack_kibana_security_exception_list.this.list_id
  item_id        = each.value.item_id
  name           = each.value.name
  description    = each.value.description
  type           = lookup(each.value, "type", "simple")
  namespace_type = var.namespace_type
  os_types       = lookup(each.value, "os_types", null)
  tags           = lookup(each.value, "tags", [])
  expire_time    = lookup(each.value, "expire_time", null)
  space_id       = var.space_id

  # NOTE: entries is a nested attribute in the elasticstack provider (Terraform
  # Framework), NOT a block type — so it must use attribute assignment.
  entries = [for e in each.value.entries : {
    field    = e.field
    type     = e.type
    operator = try(e.operator, "included")
    value    = try(e.value, null)
    values   = try(e.values, null)
  }]
}
