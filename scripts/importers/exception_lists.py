"""
exception_lists.py — bulk import for SHARED exception lists.

A "shared list" here is any non-endpoint exception list referenced by
more than one rule (or zero rules — orphan lists are still imported so
they don't disappear at apply time). Endpoint lists are explicitly
skipped per the IMPLEMENTATION_STRATEGY.

For each list we render one `.tf` under terraform/exceptions/ that calls
the existing `modules/exception_list` module with all items inlined.
Items that belong to a single-rule "rule_default" list are NOT handled
here — rule_exceptions.py owns those.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ._kibana import auth_header, paged
from .hcl import banner, esc, render_list_strings, render_string, slug


NAMESPACE = "exception_lists"
LIST_RESOURCE_ADDR = "elasticstack_kibana_security_exception_list.this"
ITEM_RESOURCE_ADDR = "elasticstack_kibana_security_exception_item.this"

# Lists with these `type` values are handled elsewhere or excluded.
EXCLUDED_LIST_TYPES = {"endpoint", "endpoint_trusted_apps", "endpoint_events",
                       "endpoint_host_isolation_exceptions", "endpoint_blocklists"}
# rule_default lists are per-rule and handled by rule_exceptions.py
RULE_DEFAULT_TYPE = "rule_default"


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------
def fetch_lists(kb: str, auth: str | None = None) -> list[dict]:
    auth = auth or auth_header()
    url = f"{kb}/api/exception_lists/_find"
    return list(paged(url, auth))


def fetch_items(kb: str, auth: str, list_id: str, namespace_type: str = "single") -> list[dict]:
    """Page items for a given exception list."""
    url = f"{kb}/api/exception_lists/items/_find"
    return list(
        paged(
            url,
            auth,
            extra_params={"list_id": list_id, "namespace_type": namespace_type},
        )
    )


def is_shared_candidate(lst: dict) -> bool:
    """Filter to lists this importer should handle."""
    t = (lst.get("type") or "").lower()
    if t in EXCLUDED_LIST_TYPES:
        return False
    if t == RULE_DEFAULT_TYPE:
        return False
    return True


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def _render_entries(entries: list[dict]) -> list[str]:
    out = ["      entries = ["]
    for e in entries or []:
        etype = (e.get("type") or "match").lower()
        if etype == "list":
            # The shared exception_list module's `entries` schema only
            # supports field/type/operator/value/values today. Emit a
            # commented placeholder so plan flags this rather than silently
            # dropping the entry. Extend modules/exception_list/variables.tf
            # to add `list = optional(object({id=string, type=string}))` to
            # round-trip these.
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


def render_tf(lst: dict, items: list[dict], module_name: str) -> str:
    """Render the .tf file for one shared exception list + its items."""
    list_id = lst.get("list_id", "")
    name = lst.get("name", "imported_list")
    description = lst.get("description", "")
    list_type = lst.get("type", "detection")
    namespace_type = lst.get("namespace_type", "single")
    tags = lst.get("tags") or []
    os_types = lst.get("os_types") or []
    kibana_id = lst.get("id", "")

    lines: list[str] = []
    lines += banner(
        name,
        "",
        "Imported from Kibana — shared exception list.",
        f"  list_id:   {list_id}",
        f"  kibana_id: {kibana_id}",
    )
    lines += ["", f'module "{module_name}" {{', '  source = "../modules/exception_list"', ""]
    lines += [
        f'  list_id        = "{esc(list_id)}"',
        f'  name           = "{esc(name)}"',
        f"  description    = {render_string(description)}",
        f'  type           = "{list_type}"',
        f'  namespace_type = "{namespace_type}"',
    ]
    if os_types:
        lines.append(f"  os_types       = {render_list_strings(os_types)}")
    if tags:
        lines.append(f"  tags           = {render_list_strings(tags)}")
    lines.append("")

    if items:
        lines.append("  items = [")
        for item in items:
            lines += _render_item(item)
        lines += ["  ]", ""]
    else:
        lines += ["  items = []", ""]

    lines += ["  space_id = var.space_id", "}", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Import blocks
# ---------------------------------------------------------------------------
def import_blocks(
    module_path: str,
    module_name: str,
    list_kibana_id: str,
    space_id: str,
    items: list[dict],
) -> str:
    """
    One block for the list itself, plus one per item — the
    exception_list module instantiates both resources.
    """
    blocks = [
        f"import {{\n"
        f"  to = module.{module_path}.module.{module_name}.{LIST_RESOURCE_ADDR}\n"
        f'  id = "{space_id}/{list_kibana_id}"\n'
        f"}}\n"
    ]
    for item in items:
        item_kid = item.get("id", "")
        item_id = item.get("item_id", "")
        if not item_kid or not item_id:
            continue
        blocks.append(
            f"import {{\n"
            f'  to = module.{module_path}.module.{module_name}.{ITEM_RESOURCE_ADDR}["{esc(item_id)}"]\n'
            f'  id = "{space_id}/{item_kid}"\n'
            f"}}\n"
        )
    return "\n".join(blocks)


# ---------------------------------------------------------------------------
# File placement (mirrors rules.py helpers)
# ---------------------------------------------------------------------------
_NUM_PREFIX = re.compile(r"^(\d+)_")


def next_index(target_dir: Path, *, start: int = 1) -> int:
    highest = 0
    for f in target_dir.glob("[0-9]*.tf"):
        m = _NUM_PREFIX.match(f.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return max(start, highest + 1)


def filename_for(lst: dict, idx: int) -> str:
    return f"{idx:03d}_{slug(lst.get('name', 'imported_list'))}.tf"


def module_name_for(lst: dict, taken: set[str]) -> str:
    base = slug(lst.get("name", "imported_list"))
    name, n = base, 2
    while name in taken:
        name = f"{base}_{n}"
        n += 1
    return name


def existing_module_names(target_dir: Path) -> set[str]:
    names: set[str] = set()
    pattern = re.compile(r'^module\s+"([^"]+)"', re.MULTILINE)
    for f in target_dir.glob("*.tf"):
        names.update(pattern.findall(f.read_text()))
    return names
