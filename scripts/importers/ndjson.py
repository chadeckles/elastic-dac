"""
ndjson.py — load Kibana NDJSON exports into the same in-memory shapes
the API-driven importers produce.

Why this exists: not every operator can reach the Kibana API from their
workstation or runner. Detection rule exports (Security → Rules → Export)
and Saved Object exports (Stack Management → Saved Objects → Export filtered
to `rule`, `exception-list`, `exception-list-agnostic`) emit NDJSON files
whose individual lines are byte-for-byte the same JSON shapes the
`/api/detection_engine/rules/_find` and `/api/exception_lists/items/_find`
endpoints return. This loader classifies those lines and groups them so
the existing renderers in `rules.py`, `exception_lists.py`, and
`rule_exceptions.py` can consume them unchanged.

The loader is read-only and never touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
# Detection rule `type` values supported by the modules/detection_rule
# module. We intentionally match loosely — unknown types still get
# classified as rules so downstream rendering can fail loudly with the
# correct rule_id rather than silently dropping the line.
_RULE_TYPES = {
    "query", "saved_query", "eql", "esql", "threshold",
    "threat_match", "machine_learning", "new_terms",
}

# NDJSON summary lines emitted at the end of an export. Skipped.
_SUMMARY_KEYS = {
    "exported_count", "exported_rules_count", "exported_exception_list_count",
    "exported_exception_list_item_count", "missing_rules", "missing_rules_count",
    "missing_exception_lists", "missing_exception_list_item_count",
    "missing_exception_lists_count", "missing_exception_list_items",
    "exported_action_connector_count", "missing_action_connection_count",
    "missing_action_connections", "excluded_action_connection_count",
    "excluded_action_connections",
}


def _is_rule(obj: dict) -> bool:
    """Heuristic: rules carry rule_id + a type from the rule taxonomy + risk_score."""
    if "item_id" in obj:  # exception items also have list_id; rule out first
        return False
    rid = obj.get("rule_id")
    rtype = (obj.get("type") or "").lower()
    if not rid:
        return False
    if rtype in _RULE_TYPES:
        return True
    # Saved-object wrapped form (`{type: "security-rule", attributes: {...}}`)
    # is *not* the detection-engine export shape; we don't support that here.
    return False


def _is_exception_list(obj: dict) -> bool:
    """Lists carry list_id + a `type` from the exception-list taxonomy and no item_id."""
    if "item_id" in obj:
        return False
    if not obj.get("list_id"):
        return False
    t = (obj.get("type") or "").lower()
    return t in {"detection", "endpoint", "rule_default"}


def _is_exception_item(obj: dict) -> bool:
    return bool(obj.get("item_id") and obj.get("list_id"))


def _is_summary(obj: dict) -> bool:
    return any(k in obj for k in _SUMMARY_KEYS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def iter_ndjson(paths: Iterable[Path]) -> Iterable[dict]:
    """Yield each JSON object from the given NDJSON files (skipping blanks)."""
    for p in paths:
        with p.open("r", encoding="utf-8") as fh:
            for ln, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"{p}: invalid JSON on line {ln}: {e.msg}"
                    ) from e


def expand_paths(arg: Path) -> list[Path]:
    """Resolve a path argument to a flat list of NDJSON files.

    - Directory → every `*.ndjson` inside (non-recursive, sorted).
    - File → singleton list (any extension; user may have renamed to `.json`).
    """
    if arg.is_dir():
        files = sorted(arg.glob("*.ndjson"))
        if not files:
            files = sorted(arg.glob("*.json"))
        if not files:
            raise FileNotFoundError(f"no .ndjson files in {arg}")
        return files
    if not arg.exists():
        raise FileNotFoundError(arg)
    return [arg]


def load_export(paths: list[Path]) -> dict:
    """Parse and group an NDJSON export.

    Returns a dict shaped to match what the API-driven dump produces:

        {
          "rules":            [rule_dict, ...],          # custom (non-immutable) only
          "exception_lists":  [{"list": {...}, "items": [...]}],   # shared lists
          "rule_exceptions":  [{"rule_id": ..., "rule_name": ...,
                                "list_ref": {...}, "items": [...]}],
        }

    Endpoint lists and lines belonging to immutable rules are dropped to
    mirror `rules.filter_custom()` and `exception_lists.is_shared_candidate()`.
    """
    rules: list[dict] = []
    lists_by_id: dict[str, dict] = {}
    items_by_list: dict[str, list[dict]] = {}
    skipped_immutable = 0
    skipped_endpoint = 0
    unknown = 0

    for obj in iter_ndjson(paths):
        if not isinstance(obj, dict) or _is_summary(obj):
            continue
        if _is_rule(obj):
            if obj.get("immutable"):
                skipped_immutable += 1
                continue
            rules.append(obj)
            continue
        if _is_exception_item(obj):
            items_by_list.setdefault(obj["list_id"], []).append(obj)
            continue
        if _is_exception_list(obj):
            t = (obj.get("type") or "").lower()
            if t.startswith("endpoint"):
                skipped_endpoint += 1
                continue
            lists_by_id[obj["list_id"]] = obj
            continue
        unknown += 1  # silently tolerated; future-proof for new export shapes

    # ---- group: shared exception lists (type=detection) -----------------
    shared: list[dict] = []
    rule_default_lists: dict[str, dict] = {}
    for lid, lst in lists_by_id.items():
        t = (lst.get("type") or "").lower()
        if t == "rule_default":
            rule_default_lists[lid] = lst
        else:
            shared.append({"list": lst, "items": items_by_list.get(lid, [])})

    # ---- group: rule-scoped exceptions ----------------------------------
    # Match each rule's `exceptions_list[]` rule_default ref to its items.
    rule_exceptions: list[dict] = []
    for r in rules:
        ref = next(
            (x for x in (r.get("exceptions_list") or [])
             if (x.get("type") or "").lower() == "rule_default"),
            None,
        )
        if not ref:
            continue
        lid = ref.get("list_id") or ""
        items = items_by_list.get(lid, [])
        if not items:
            continue
        rule_exceptions.append({
            "rule_id": r.get("rule_id"),
            "rule_name": r.get("name"),
            "list_ref": ref,
            "items": items,
        })

    return {
        "rules": rules,
        "exception_lists": shared,
        "rule_exceptions": rule_exceptions,
        "_stats": {
            "skipped_immutable_rules": skipped_immutable,
            "skipped_endpoint_lists": skipped_endpoint,
            "unclassified_lines": unknown,
            "rule_default_lists_seen": len(rule_default_lists),
        },
    }
