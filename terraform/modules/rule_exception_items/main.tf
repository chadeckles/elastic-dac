# =============================================================================
# Module: rule_exception_items
# =============================================================================
# Creates one or more elasticstack_kibana_security_exception_item resources
# attached to an EXISTING exception list. This is the "production-default"
# pattern in Elastic Security: most exceptions are rule-scoped items that
# live on a rule's auto-created default list, NOT on a shared list.
#
# Use this module to:
#   • Add items to a rule-default list created by another rule's module call
#     (pass that rule's `rule_default_exception_list_id` output as list_id).
#   • Add items to a Kibana-managed exception list whose list_id is known
#     (e.g. a list originally created via the GUI and now under DaC control).
#
# For a SHARED list (one list, many rules) keep using modules/exception_list,
# which still creates the list container itself.
#
# Reference:
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

resource "elasticstack_kibana_security_exception_item" "this" {
  for_each = { for item in var.items : item.item_id => item }

  list_id        = var.list_id
  item_id        = each.value.item_id
  name           = each.value.name
  description    = each.value.description
  type           = lookup(each.value, "type", "simple")
  namespace_type = var.namespace_type
  os_types       = lookup(each.value, "os_types", null)
  tags           = lookup(each.value, "tags", [])
  expire_time    = lookup(each.value, "expire_time", null)
  space_id       = var.space_id

  entries = [for e in each.value.entries : {
    field    = e.field
    type     = e.type
    operator = try(e.operator, "included")
    value    = try(e.value, null)
    values   = try(e.values, null)
  }]
}
