"""
rules.py — bulk import for custom (non-immutable) detection rules.

Renders one `.tf` file per rule under terraform/custom_rules/, mirroring
the `module "<slug>" { source = "../modules/detection_rule" ... }` shape
the repo already uses. Skips immutable (Elastic-prebuilt) rules — those
are managed via terraform/prebuilt_rules.tf.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ._kibana import auth_header, paged
from .hcl import banner, esc, render_list_strings, render_string, slug


NAMESPACE = "rules"
RESOURCE_ADDR = "elasticstack_kibana_security_detection_rule.this"


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------
def fetch_all(kb: str, auth: str | None = None) -> list[dict]:
    """Return every detection rule in the configured space, custom + prebuilt."""
    auth = auth or auth_header()
    url = f"{kb}/api/detection_engine/rules/_find"
    return list(
        paged(
            url,
            auth,
            extra_params={"sort_field": "name", "sort_order": "asc"},
        )
    )


def filter_custom(rules: list[dict]) -> list[dict]:
    """Drop immutable (Elastic prebuilt) rules — they're managed elsewhere."""
    return [r for r in rules if not r.get("immutable")]


# ---------------------------------------------------------------------------
# Threat → mitre_attack
# ---------------------------------------------------------------------------
def _to_mitre_attack(threat: list[dict]) -> list[dict] | None:
    """
    Collapse Kibana's verbose threat[] into the simplified mitre_attack[]
    shape this repo's detection_rule module expects.

    Falls back to None when the structure is unexpected; the generator then
    emits the raw `threat` list verbatim so nothing is lost.
    """
    out: list[dict] = []
    for entry in threat or []:
        framework = entry.get("framework", "MITRE ATT&CK")
        if framework != "MITRE ATT&CK":
            return None
        tactic = (entry.get("tactic") or {}).get("id")
        if not tactic:
            return None
        techs, subs = [], []
        for t in entry.get("technique", []) or []:
            tid = t.get("id")
            if tid:
                techs.append(tid)
            for s in t.get("subtechnique", []) or []:
                sid = s.get("id")
                if sid:
                    subs.append(sid)
        out.append({"tactic": tactic, "techniques": techs, "subtechniques": subs})
    return out or None


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def _render_mitre(mitre: list[dict]) -> list[str]:
    lines = ["  mitre_attack = ["]
    for m in mitre:
        techs = ", ".join(f'"{t}"' for t in m.get("techniques", []))
        subs = ", ".join(f'"{s}"' for s in m.get("subtechniques", []))
        lines.append(
            f'    {{ tactic = "{m["tactic"]}", '
            f"techniques = [{techs}], subtechniques = [{subs}] }},"
        )
    lines.append("  ]")
    return lines


def _render_threat_verbose(threat: list[dict]) -> list[str]:
    """Fallback when we can't simplify to mitre_attack."""
    lines = ["  threat = ["]
    for t in threat:
        tac = t.get("tactic", {})
        lines += [
            "    {",
            "      framework = \"MITRE ATT&CK\",",
            "      tactic = {",
            f'        id        = "{tac.get("id", "")}",',
            f'        name      = "{esc(tac.get("name", ""))}",',
            f'        reference = "{tac.get("reference", "")}",',
            "      },",
            "      technique = [",
        ]
        for tech in t.get("technique", []) or []:
            lines += [
                "        {",
                f'          id        = "{tech.get("id", "")}",',
                f'          name      = "{esc(tech.get("name", ""))}",',
                f'          reference = "{tech.get("reference", "")}",',
                "          subtechnique = [",
            ]
            for s in tech.get("subtechnique", []) or []:
                lines += [
                    "            {",
                    f'              id        = "{s.get("id", "")}",',
                    f'              name      = "{esc(s.get("name", ""))}",',
                    f'              reference = "{s.get("reference", "")}",',
                    "            },",
                ]
            lines += ["          ],", "        },"]
        lines += ["      ],", "    },"]
    lines.append("  ]")
    return lines


def _render_exceptions_list(refs: list[dict]) -> list[str]:
    if not refs:
        return []
    out = ["  exceptions_list = ["]
    for r in refs:
        out += [
            "    {",
            f'      id             = "{r.get("id", "")}",',
            f'      list_id        = "{r.get("list_id", "")}",',
            f'      namespace_type = "{r.get("namespace_type", "single")}",',
            f'      type           = "{r.get("type", "detection")}",',
            "    },",
        ]
    out.append("  ]")
    return out


def _render_alert_suppression(sup: dict) -> list[str]:
    """Render the alert_suppression nested object."""
    group_by = sup.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    lines = ["  alert_suppression = {", f"    group_by = {render_list_strings(group_by, indent=4)}"]
    if sup.get("duration"):
        d = sup["duration"]
        # Kibana returns {"value": 5, "unit": "m"} OR a plain string like "5m".
        if isinstance(d, dict):
            lines.append(f'    duration = "{d.get("value", 5)}{d.get("unit", "m")}"')
        else:
            lines.append(f'    duration = "{d}"')
    if sup.get("missing_fields_strategy"):
        lines.append(f'    missing_fields_strategy = "{sup["missing_fields_strategy"]}"')
    lines.append("  }")
    return lines


def render_tf(rule: dict, module_name: str) -> str:
    """Render a single rule's `.tf` content.

    Field ordering matches the convention used by hand-authored rule files
    so `terraform fmt` and reviewer diffs stay stable. Field coverage is
    intentionally broad — anything Kibana returns that the
    detection_rule module accepts is round-tripped here so the post-import
    `terraform plan` is a true 0/0/0 instead of an N-line "1 to change"
    spree of dropped optional fields.
    """
    name = rule.get("name", "imported_rule")
    rid = rule.get("rule_id", "")
    kibana_id = rule.get("id", "")
    rtype = rule.get("type", "query")
    sev = rule.get("severity", "medium")
    risk = rule.get("risk_score", 50)
    desc = rule.get("description", "")
    enabled = bool(rule.get("enabled", False))
    interval = rule.get("interval", "5m")
    from_val = rule.get("from", "now-6m")
    to_val = rule.get("to", "now")
    max_signals = rule.get("max_signals")
    tags = list(rule.get("tags", []))
    indices = rule.get("index") or []
    threat = rule.get("threat") or []

    if not any(t.startswith("Team:") for t in tags):
        tags.append("Team: Imported")

    # Detect features the module/importer can't fully round-trip yet so the
    # banner warns reviewers before they hit a "1 to change" plan.
    warnings: list[str] = []
    for ref in rule.get("exceptions_list") or []:
        # informational only — list-operator entry detection happens in
        # exception_lists.py / rule_exceptions.py
        pass
    if rule.get("response_actions"):
        warnings.append("Has response_actions — not yet rendered by importer; will plan as drift.")
    if rule.get("investigation_fields"):
        warnings.append("Has investigation_fields — not yet rendered by importer; will plan as drift.")
    if rule.get("data_view_id"):
        warnings.append("Has data_view_id — not yet rendered by importer; will plan as drift.")
    if rtype == "threat_match" and rule.get("threat_mapping"):
        warnings.append("threat_match rule has threat_mapping — module variable missing; "
                        "extend modules/detection_rule before merging.")

    lines: list[str] = []
    banner_lines = [
        name,
        "",
        "Imported from Kibana — review before merging.",
        f"  rule_id:   {rid}",
        f"  kibana_id: {kibana_id}  ← use THIS id for terraform import",
    ]
    if warnings:
        banner_lines += ["", "  ⚠ IMPORT WARNINGS:"] + [f"    - {w}" for w in warnings]
    lines += banner(*banner_lines)
    lines += ["", f'module "{module_name}" {{', '  source = "../modules/detection_rule"', ""]
    lines += [
        f'  name        = "{esc(name)}"',
        f"  description = {render_string(desc)}",
        f'  type        = "{rtype}"',
        f'  severity    = "{sev}"',
        f"  risk_score  = {risk}",
        f'  rule_id     = "{rid}"',
        "",
    ]

    # Query / language — only set if rule type uses them.
    query = rule.get("query")
    lang = rule.get("language")
    if query is not None:
        lines.append(f"  query    = {render_string(query)}")
    if lang:
        lines.append(f'  language = "{lang}"')
    if query is not None or lang:
        lines.append("")

    # Scheduling
    lines += [
        f'  from     = "{from_val}"',
        f'  to       = "{to_val}"',
        f'  interval = "{interval}"',
    ]
    if max_signals is not None:
        lines.append(f"  max_signals = {max_signals}")
    lines.append("")

    if indices:
        lines += [f"  index = {render_list_strings(indices)}", ""]

    lines += [f"  tags = {render_list_strings(tags)}", ""]

    # ---- Triage / metadata passthroughs --------------------------------
    fp = rule.get("false_positives") or []
    if fp:
        lines += [f"  false_positives = {render_list_strings(fp)}", ""]

    refs = rule.get("references") or []
    if refs:
        lines += [f"  references = {render_list_strings(refs)}", ""]

    note = rule.get("note")
    if note:
        lines += [f"  note = {render_string(note)}", ""]

    setup = rule.get("setup")
    if setup:
        lines += [f"  setup = {render_string(setup)}", ""]

    # ---- Less-common but supported fields ------------------------------
    bbt = rule.get("building_block_type")
    if bbt:
        lines.append(f'  building_block_type = "{bbt}"')

    tso = rule.get("timestamp_override")
    if tso:
        lines.append(f'  timestamp_override = "{tso}"')

    tl_id = rule.get("timeline_id")
    if tl_id:
        lines.append(f'  timeline_id    = "{tl_id}"')
    tl_title = rule.get("timeline_title")
    if tl_title:
        lines.append(f'  timeline_title = "{esc(tl_title)}"')

    author = rule.get("author")
    if author:
        if isinstance(author, str):
            author = [author]
        lines.append(f"  author = {render_list_strings(author)}")

    if rule.get("license"):
        lines.append(f'  license = "{esc(rule["license"])}"')
    if rule.get("version") is not None:
        lines.append(f"  rule_version = {rule['version']}")

    if any([bbt, tso, tl_id, tl_title, author, rule.get("license"), rule.get("version") is not None]):
        lines.append("")

    # ---- Type-specific fields ------------------------------------------
    # Threshold rules.
    threshold = rule.get("threshold")
    if threshold:
        fields = threshold.get("field") or []
        if isinstance(fields, str):
            fields = [fields]
        lines += [
            "  threshold = {",
            f'    field = {render_list_strings(fields, indent=4) if fields else "[]"},',
            f'    value = {threshold.get("value", 1)},',
            "  }",
            "",
        ]

    # New-terms rules.
    if rtype == "new_terms":
        nt_fields = rule.get("new_terms_fields") or []
        hws = rule.get("history_window_start")
        if nt_fields:
            lines += [f"  new_terms_fields = {render_list_strings(nt_fields)}"]
        if hws:
            lines += [f'  history_window_start = "{hws}"']
        if nt_fields or hws:
            lines.append("")

    # ML rules.
    if rtype == "machine_learning":
        ml_jobs = rule.get("machine_learning_job_id") or []
        if isinstance(ml_jobs, str):
            ml_jobs = [ml_jobs]
        if ml_jobs:
            lines += [f"  machine_learning_job_id = {render_list_strings(ml_jobs)}"]
        if rule.get("anomaly_threshold") is not None:
            lines += [f"  anomaly_threshold = {rule['anomaly_threshold']}"]
        lines.append("")

    # Threat-match (indicator match) rules.
    if rtype == "threat_match":
        ti = rule.get("threat_index") or []
        if ti:
            lines.append(f"  threat_index = {render_list_strings(ti)}")
        if rule.get("threat_query"):
            lines.append(f"  threat_query = {render_string(rule['threat_query'])}")
        if rule.get("threat_indicator_path"):
            lines.append(f'  threat_indicator_path = "{esc(rule["threat_indicator_path"])}"')
        # threat_mapping is NOT yet a module variable — see banner warning.
        lines.append("")

    # MITRE — emit verbose `threat = [...]` directly so we don't depend on
    # the static lookup table in modules/detection_rule/mitre_lookup.tf
    # being a complete superset of every technique referenced across the
    # Kibana environment. The Kibana payload already carries name +
    # reference for every tactic/technique/subtechnique, so verbose is
    # both the most faithful and the most failure-resistant choice for
    # imported rules. The simplified `mitre_attack` form is intended for
    # hand-authored rules where the engineer just wants to type IDs.
    if threat:
        lines += _render_threat_verbose(threat)
    lines.append("")

    # Existing exception list refs (preserved verbatim — the lists themselves
    # are imported by exception_lists.py / rule_exceptions.py).
    lines += _render_exceptions_list(rule.get("exceptions_list") or [])

    # Alert suppression (provider-supported on most rule types).
    sup = rule.get("alert_suppression")
    if sup and (sup.get("group_by") or sup.get("groupBy")):
        # Kibana sometimes camelCases this on the wire.
        if "groupBy" in sup and "group_by" not in sup:
            sup = {**sup, "group_by": sup["groupBy"]}
        lines += _render_alert_suppression(sup)
        lines.append("")

    lines += [
        f"  enabled      = {'true' if enabled else 'false'}",
        "  space_id     = var.space_id",
        "  default_tags = var.default_tags",
        "}",
        "",
    ]
    return "\n".join(lines)


def import_block(module_path: str, module_name: str, kibana_id: str, space_id: str) -> str:
    """Generate a Terraform 1.5 `import {}` block for one rule."""
    return (
        f"import {{\n"
        f"  to = module.{module_path}.module.{module_name}.{RESOURCE_ADDR}\n"
        f'  id = "{space_id}/{kibana_id}"\n'
        f"}}\n"
    )


# ---------------------------------------------------------------------------
# File placement
# ---------------------------------------------------------------------------
_NUM_PREFIX = re.compile(r"^(\d+)_")


def next_index(target_dir: Path, *, start: int = 1) -> int:
    """Find the next NNN_ prefix to use in target_dir."""
    highest = 0
    for f in target_dir.glob("[0-9]*.tf"):
        m = _NUM_PREFIX.match(f.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return max(start, highest + 1)


def filename_for(rule: dict, idx: int) -> str:
    return f"{idx:03d}_{slug(rule.get('name', 'imported_rule'))}.tf"


def existing_module_names(target_dir: Path) -> set[str]:
    """Cheap scan of `module "<name>"` declarations to avoid collisions."""
    names: set[str] = set()
    pattern = re.compile(r'^module\s+"([^"]+)"', re.MULTILINE)
    for f in target_dir.glob("*.tf"):
        names.update(pattern.findall(f.read_text()))
    return names
