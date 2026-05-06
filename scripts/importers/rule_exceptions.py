"""
rule_exceptions.py — bulk import for rule-scoped exception items.

In production Elastic Security, the most common pattern is "I clicked
'Add rule exception' in the Kibana Rules UI and it wrote an item to that
rule's auto-created rule-default exception list." Those per-rule items
land in this repo under terraform/rule_exceptions/ via the
modules/rule_exception_items module — the rule itself owns the list, and
analysts add tuning items into it without touching the rule resource.

This importer:
  1. Walks every imported custom rule.
  2. For each `exceptions_list[]` ref of type=rule_default, fetches the
     items in that list.
  3. Renders one .tf per rule with non-empty rule-default items.
  4. Emits per-item Terraform 1.5 `import {}` blocks.
  5. Returns the (rule_module_name → list_id) map so the orchestrator
     can update terraform/custom_rules/outputs.tf and the variable
     `rule_default_lists` plumbed through main.tf.

It does NOT create the rule-default list itself — that resource is born
when Kibana first creates the rule, and is already represented in code
by the parent rule's module call (which exposes
`rule_default_exception_list_id` as an output). We only import the
items.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ._kibana import auth_header
from .exception_lists import fetch_items
from .hcl import banner, esc, render_list_strings, render_string, slug


NAMESPACE = "rule_exceptions"
ITEM_RESOURCE_ADDR = "elasticstack_kibana_security_exception_item.this"


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------
def find_rule_default_list_ref(rule: dict) -> dict | None:
    """Pull the rule_default exception list reference off a rule, if any."""
    for ref in rule.get("exceptions_list") or []:
        if (ref.get("type") or "").lower() == "rule_default":
            return ref
    return None


def fetch_for_rule(kb: str, auth: str, rule: dict) -> tuple[dict | None, list[dict]]:
    """Return (list_ref, items) for a rule's rule-default list, or (None, [])."""
    ref = find_rule_default_list_ref(rule)
    if not ref:
        return None, []
    items = fetch_items(
        kb,
        auth,
        list_id=ref.get("list_id", ""),
        namespace_type=ref.get("namespace_type", "single"),
    )
    return ref, items


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def _render_entries(entries: list[dict]) -> list[str]:
    out = ["      entries = ["]
    for e in entries or []:
        etype = (e.get("type") or "match").lower()
        if etype == "list":
            ref = e.get("list") or {}
            out.append("        # TODO: list-operator entry not yet supported by module schema")
            out.append("        # original: field={f!r} list_id={lid!r} type={lt!r}".format(
                f=e.get("field", ""), lid=ref.get("id", ""), lt=ref.get("type", "")
            ))
            out.append("        # {")
            out.append(f'        #   field    = "{esc(e.get("field", ""))}"')
            out.append('        #   type     = "list"')
            out.append(f'        #   operator = "{esc(e.get("operator", "included"))}"')
            out.append(f'        #   list     = {{ id = "{ref.get("id", "")}", type = "{ref.get("type", "")}" }}')
            out.append("        # },")
            continue
        out.append("        {")
        out.append(f'          field    = "{esc(e.get("field", ""))}"')
        out.append(f'          type     = "{esc(etype)}"')
        out.append(f'          operator = "{esc(e.get("operator", "included"))}"')
        if "value" in e and e["value"] is not None and "values" not in e:
            out.append(f"          value    = {render_string(e.get('value'))}")
        if "values" in e and e["values"] is not None:
            out.append(f"          values   = {render_list_strings(e.get('values') or [])}")
        out.append("        },")
    out.append("      ]")
    return out


def _render_item(item: dict) -> list[str]:
    lines = ["    {"]
    lines.append(f'      item_id     = "{esc(item.get("item_id", ""))}"')
    lines.append(f'      name        = "{esc(item.get("name", ""))}"')
    lines.append(f"      description = {render_string(item.get('description', ''))}")
    if item.get("type") and item["type"] != "simple":
        lines.append(f'      type        = "{item["type"]}"')
    if item.get("os_types"):
        lines.append(f"      os_types    = {render_list_strings(item['os_types'])}")
    tags = item.get("tags") or []
    if tags:
        lines.append(f"      tags        = {render_list_strings(tags)}")
    if item.get("expire_time"):
        lines.append(f'      expire_time = "{item["expire_time"]}"')
    lines += _render_entries(item.get("entries") or [])
    lines.append("    },")
    return lines


def render_tf(rule_module_name: str, rule_name: str, items: list[dict]) -> str:
    """Render the .tf file that attaches per-rule items to the rule-default list."""
    extras_module = f"{rule_module_name}_extras"

    lines: list[str] = []
    lines += banner(
        f"{rule_name} — rule-scoped exception items",
        "",
        "Imported from the rule's rule-default list. Edit here to tune the",
        "rule without modifying the rule resource itself.",
    )
    lines += [
        "",
        f'module "{extras_module}" {{',
        '  source = "../modules/rule_exception_items"',
        "",
        f'  list_id  = var.rule_default_lists["{rule_module_name}"]',
        "  space_id = var.space_id",
        "",
        "  items = [",
    ]
    for item in items:
        lines += _render_item(item)
    lines += ["  ]", "}", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Import blocks
# ---------------------------------------------------------------------------
def import_blocks(
    module_path: str,
    rule_module_name: str,
    items: list[dict],
    space_id: str,
) -> str:
    extras_module = f"{rule_module_name}_extras"
    blocks: list[str] = []
    for item in items:
        item_kid = item.get("id", "")
        item_id = item.get("item_id", "")
        if not item_kid or not item_id:
            continue
        blocks.append(
            f"import {{\n"
            f'  to = module.{module_path}.module.{extras_module}.{ITEM_RESOURCE_ADDR}["{esc(item_id)}"]\n'
            f'  id = "{space_id}/{item_kid}"\n'
            f"}}\n"
        )
    return "\n".join(blocks)


# ---------------------------------------------------------------------------
# File placement
# ---------------------------------------------------------------------------
_NUM_PREFIX = re.compile(r"^(\d+)_")


def next_index(target_dir: Path, *, start: int = 1) -> int:
    highest = 0
    for f in target_dir.glob("[0-9]*.tf"):
        m = _NUM_PREFIX.match(f.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return max(start, highest + 1)


def filename_for(rule_module_name: str, idx: int) -> str:
    return f"{idx:03d}_{rule_module_name}_extras.tf"
