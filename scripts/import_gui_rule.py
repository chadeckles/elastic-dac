#!/usr/bin/env python3
# =============================================================================
# import_gui_rule.py — Fetch a rule from Kibana and generate a .tf file
# =============================================================================
# Simple helper for the "create in GUI → bring into Terraform" workflow.
#
# Usage:
#   python3 scripts/import_gui_rule.py --list                     # List rules
#   python3 scripts/import_gui_rule.py --name "My Rule Name"      # Import by name
#   python3 scripts/import_gui_rule.py --rule-id <uuid>           # Import by ID
#
# Generates a .tf file in terraform/custom_rules/ that you review, adjust,
# register in outputs.tf, and then `terraform import` into state.
#
# Environment / .env:
#   KIBANA_ENDPOINT    (default: http://localhost:5601)
#   KIBANA_USERNAME    (default: elastic)
#   KIBANA_PASSWORD    (default: changeme)
# =============================================================================

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
from base64 import b64encode
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CUSTOM_RULES_DIR = PROJECT_ROOT / "terraform" / "custom_rules"


# ---------------------------------------------------------------------------
# Kibana API
# ---------------------------------------------------------------------------
def _auth(user: str, pwd: str) -> str:
    return f"Basic {b64encode(f'{user}:{pwd}'.encode()).decode()}"


def _get(url: str, auth: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": auth, "kbn-xsrf": "true",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        print(f"  ✗ Connection failed: {e}", file=sys.stderr)
        sys.exit(1)


def list_rules(kb: str, auth: str) -> list[dict]:
    rules, page = [], 1
    while True:
        resp = _get(f"{kb}/api/detection_engine/rules/_find?per_page=100&page={page}&sort_field=name&sort_order=asc", auth)
        data = resp.get("data", [])
        if not data:
            break
        rules.extend(data)
        if page * 100 >= resp.get("total", 0):
            break
        page += 1
    return rules


def find_rule(kb: str, auth: str, name: str) -> list[dict]:
    all_rules = list_rules(kb, auth)
    q = name.lower()
    return [r for r in all_rules if q in r.get("name", "").lower()]


def get_rule(kb: str, auth: str, rule_id: str) -> dict:
    return _get(f"{kb}/api/detection_engine/rules?rule_id={rule_id}", auth)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _snake(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_")
    return ("rule_" + s) if s and s[0].isdigit() else s


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


def _next_num(d: Path) -> int:
    files = sorted(d.glob("[0-9]*.tf"))
    if not files:
        return 6  # after existing 005_ rules
    m = re.match(r"(\d+)", files[-1].name)
    return int(m.group(1)) + 1 if m else 6


# ---------------------------------------------------------------------------
# .tf generation — intentionally simple, meant to be hand-edited after
# ---------------------------------------------------------------------------
def rule_to_tf(rule: dict, idx: int) -> tuple[str, str, str]:
    """Returns (filename, module_name, tf_content)."""
    name = rule.get("name", "imported_rule")
    mod = _snake(name)
    fname = f"{idx:03d}_{mod}.tf"
    rtype = rule.get("type", "query")
    sev = rule.get("severity", "medium")
    risk = rule.get("risk_score", 50)
    desc = rule.get("description", "")
    query = rule.get("query", "")
    lang = rule.get("language", "kuery")
    enabled = str(rule.get("enabled", False)).lower()
    rid = rule.get("rule_id", "")
    kibana_id = rule.get("id", "")  # internal Kibana document ID (needed for terraform import)
    interval = rule.get("interval", "5m")
    from_val = rule.get("from", "now-6m")
    tags = rule.get("tags", [])
    indices = rule.get("index", [])
    threat = rule.get("threat", [])

    if not any(t.startswith("Team:") for t in tags):
        tags.append("Team: Imported")

    lines = [
        f"# =============================================================================",
        f"# {name}",
        f"# =============================================================================",
        f"# Imported from Kibana — review and adjust before committing.",
        f"#",
        f"# rule_id:   {rid}",
        f"# kibana_id: {kibana_id}  ← use THIS id for terraform import",
        f"# =============================================================================",
        f"",
        f'module "{mod}" {{',
        f'  source = "../modules/detection_rule"',
        f"",
        f'  name        = "{_esc(name)}"',
    ]

    if "\n" in desc:
        lines += [f"  description = <<-EOT", f"    {desc}", f"  EOT"]
    else:
        lines.append(f'  description = "{_esc(desc)}"')

    lines += [
        f'  type        = "{rtype}"',
        f'  severity    = "{sev}"',
        f"  risk_score  = {risk}",
        f'  rule_id     = "{rid}"',
        "",
    ]

    if query:
        if "\n" in query or len(query) > 90:
            lines += [f"  query = <<-EOQ", f"    {query}", f"  EOQ"]
        else:
            lines.append(f'  query    = "{_esc(query)}"')
        lines.append(f'  language = "{lang}"')

    lines += [f'  from     = "{from_val}"', f'  interval = "{interval}"', ""]

    if indices:
        items = ",\n".join(f'    "{i}"' for i in indices)
        lines += [f"  index = [", items + ",", "  ]", ""]

    tag_items = ",\n".join(f'    "{_esc(t)}"' for t in tags)
    lines += [f"  tags = [", tag_items + ",", "  ]", ""]

    # MITRE threat
    if threat:
        lines.append("  threat = [")
        for t in threat:
            tac = t.get("tactic", {})
            lines += [
                "    {",
                "      tactic = {",
                f'        id        = "{tac.get("id", "")}"',
                f'        name      = "{_esc(tac.get("name", ""))}"',
                f'        reference = "{tac.get("reference", "")}"',
                "      }",
            ]
            techs = t.get("technique", [])
            if techs:
                lines.append("      technique = [")
                for tech in techs:
                    lines += [
                        "        {",
                        f'          id        = "{tech.get("id", "")}"',
                        f'          name      = "{_esc(tech.get("name", ""))}"',
                        f'          reference = "{tech.get("reference", "")}"',
                    ]
                    subs = tech.get("subtechnique", [])
                    if subs:
                        lines.append("          subtechnique = [")
                        for s in subs:
                            lines += [
                                "            {",
                                f'              id        = "{s.get("id", "")}"',
                                f'              name      = "{_esc(s.get("name", ""))}"',
                                f'              reference = "{s.get("reference", "")}"',
                                "            },",
                            ]
                        lines.append("          ]")
                    else:
                        lines.append("          subtechnique = []")
                    lines.append("        },")
                lines.append("      ]")
            else:
                lines.append("      technique = []")
            lines.append("    },")
        lines.append("  ]")
    else:
        lines.append("  threat = []")

    lines += [
        "",
        f"  enabled      = {enabled}",
        "  space_id     = var.space_id",
        "  default_tags = var.default_tags",
        "}",
        "",
    ]

    return fname, mod, "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Import a Kibana rule into Terraform.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--rule-id", help="Import by rule_id (UUID).")
    g.add_argument("--name", help="Search by name (partial match).")
    g.add_argument("--list", action="store_true", help="List all rules.")
    p.add_argument("--kibana-url", default=None)
    args = p.parse_args()

    kb = (args.kibana_url or os.environ.get("KIBANA_ENDPOINT", "http://localhost:5601")).rstrip("/")
    auth = _auth(os.environ.get("KIBANA_USERNAME", "elastic"),
                 os.environ.get("KIBANA_PASSWORD", "changeme"))

    # --- List ---
    if args.list:
        print(f"\n{'═' * 70}\n  Detection Rules in Kibana ({kb})\n{'═' * 70}")
        for r in list_rules(kb, auth):
            kind = "prebuilt" if r.get("immutable") else "custom  "
            on = "✓" if r.get("enabled") else "✗"
            print(f"  {on} [{kind}]  {r['name']:<45}  {r.get('rule_id', '?')}")
        print()
        return

    if not args.rule_id and not args.name:
        p.error("Provide --rule-id, --name, or --list.")

    # --- Fetch ---
    if args.rule_id:
        rule = get_rule(kb, auth, args.rule_id)
    else:
        matches = find_rule(kb, auth, args.name)
        if not matches:
            print("  ✗ No matching rules.")
            sys.exit(1)
        if len(matches) == 1:
            rule = matches[0]
        else:
            print(f"\n  Found {len(matches)} matches:\n")
            for i, r in enumerate(matches, 1):
                print(f"    [{i}] {r['name']}")
            c = input("\n  Pick a number (q to quit): ").strip()
            if c.lower() == "q":
                return
            rule = matches[int(c) - 1]

    # --- Generate ---
    idx = _next_num(CUSTOM_RULES_DIR)
    fname, mod, content = rule_to_tf(rule, idx)
    out = CUSTOM_RULES_DIR / fname
    out.write_text(content)

    rid = rule.get("rule_id", "")
    kibana_id = rule.get("id", "")
    print(f"""
{'═' * 60}
  ✓ Generated: terraform/custom_rules/{fname}
{'═' * 60}

  Next steps (manual):

  1. Review and edit the generated file

  2. Add to terraform/custom_rules/outputs.tf:
     {mod:<40}= module.{mod}.rule_id

  3. Register the new module:
     cd terraform && terraform init

  4. Import into Terraform state:
     cd terraform
     terraform import \\
       'module.custom_rules.module.{mod}.elasticstack_kibana_security_detection_rule.this' \\
       'default/{kibana_id}'

  5. Verify:  terraform plan

  ⚠  IMPORTANT: The import command uses the internal Kibana
     document id ({kibana_id}), NOT the rule_id.
     These are different UUIDs! The rule_id is {rid}.
""")


if __name__ == "__main__":
    main()
