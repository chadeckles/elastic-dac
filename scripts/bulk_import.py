#!/usr/bin/env python3
"""
bulk_import.py — brownfield bulk importer for Elastic DaC.

Pulls the live Kibana configuration (custom detection rules, shared
exception lists, and rule-scoped exception items) into this repo as
Terraform files plus matching `import {}` blocks. Endpoint lists are
intentionally excluded — see IMPLEMENTATION_STRATEGY.md.

Two-phase workflow (matches IMPLEMENTATION_STRATEGY.md → Phase 1):

  1. DUMP — fetch from Kibana, cache JSON locally so we can iterate on
            rendering without re-hitting prod.
  2. RENDER — generate .tf files + imports.tf + import.sh from the cache.

Usage:
  # Full pipeline (dump + render) for everything:
  python3 scripts/bulk_import.py

  # Just dump:
  python3 scripts/bulk_import.py --dump-only

  # Render from a previously-cached dump (no Kibana calls):
  python3 scripts/bulk_import.py --from-cache 2026-05-01

  # Limit scope:
  python3 scripts/bulk_import.py --only rules
  python3 scripts/bulk_import.py --only rules,exception_lists,rule_exceptions

  # Dry run — show what would be written, change nothing:
  python3 scripts/bulk_import.py --dry-run

Environment:
  KIBANA_ENDPOINT  https://....kb....:9243
  KIBANA_API_KEY   <encoded>

Exit codes:
  0  success
  1  config / connectivity error
  2  generator error (e.g. unknown rule type)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Iterable

# Make `from importers import …` work whether invoked as a module
# (`python3 -m scripts.bulk_import`) or as a script
# (`python3 scripts/bulk_import.py`).
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from importers import _kibana, exception_lists, rule_exceptions, rules  # noqa: E402
from importers.hcl import slug  # noqa: E402


CUSTOM_RULES_DIR = PROJECT_ROOT / "terraform" / "custom_rules"
EXCEPTIONS_DIR = PROJECT_ROOT / "terraform" / "exceptions"
RULE_EXCEPTIONS_DIR = PROJECT_ROOT / "terraform" / "rule_exceptions"
TF_DIR = PROJECT_ROOT / "terraform"

DEFAULT_TARGETS = ("rules", "exception_lists", "rule_exceptions")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--kibana-url", default=None, help="Override KIBANA_ENDPOINT.")
    p.add_argument("--space-id", default="default", help="Kibana space (default: default).")
    p.add_argument(
        "--only",
        default=",".join(DEFAULT_TARGETS),
        help=f"Comma-separated subset of {DEFAULT_TARGETS}.",
    )
    p.add_argument("--dump-only", action="store_true", help="Fetch + cache, skip rendering.")
    p.add_argument("--from-cache", metavar="DUMP_ID", help="Skip fetching, render this cached dump.")
    p.add_argument("--dry-run", action="store_true", help="Render to stdout summary only.")
    p.add_argument(
        "--dump-id",
        default=_dt.date.today().isoformat(),
        help="Cache namespace name (default: today's date).",
    )
    return p.parse_args()


def parse_targets(arg: str) -> set[str]:
    chosen = {t.strip() for t in arg.split(",") if t.strip()}
    bad = chosen - set(DEFAULT_TARGETS)
    if bad:
        sys.exit(f"  ✗ unknown --only target(s): {', '.join(sorted(bad))}")
    return chosen


# ---------------------------------------------------------------------------
# Dump phase
# ---------------------------------------------------------------------------
def dump(kb: str, auth: str, dump_id: str, targets: set[str]) -> Path:
    print(f"\n  → dumping live Kibana config to .import-cache/{dump_id}/\n")

    if "rules" in targets or "rule_exceptions" in targets:
        cache = _kibana.cache_dir(PROJECT_ROOT, "rules", dump_id)
        all_rules = rules.fetch_all(kb, auth)
        custom = rules.filter_custom(all_rules)
        _kibana.write_cache(cache / "_index.json", [r.get("rule_id") for r in custom])
        for r in custom:
            rid = r.get("rule_id") or r.get("id")
            _kibana.write_cache(cache / f"{rid}.json", r)
        print(f"    ✓ rules: {len(custom)} custom rules cached "
              f"({len(all_rules) - len(custom)} immutable skipped)")

    if "exception_lists" in targets:
        cache = _kibana.cache_dir(PROJECT_ROOT, "exception_lists", dump_id)
        lists = exception_lists.fetch_lists(kb, auth)
        shared = [l for l in lists if exception_lists.is_shared_candidate(l)]
        _kibana.write_cache(cache / "_index.json", [l.get("list_id") for l in shared])
        for lst in shared:
            list_id = lst.get("list_id")
            payload = {
                "list": lst,
                "items": exception_lists.fetch_items(
                    kb, auth, list_id=list_id,
                    namespace_type=lst.get("namespace_type", "single"),
                ),
            }
            _kibana.write_cache(cache / f"{slug(list_id)}.json", payload)
        print(f"    ✓ exception_lists: {len(shared)} shared lists cached "
              f"({len(lists) - len(shared)} endpoint/rule_default skipped)")

    if "rule_exceptions" in targets:
        # Reuses the rules cache; pulls items per rule that has a rule_default ref.
        rule_cache = _kibana.cache_dir(PROJECT_ROOT, "rules", dump_id)
        rxc = _kibana.cache_dir(PROJECT_ROOT, "rule_exceptions", dump_id)
        index: list[str] = []
        for rfile in sorted(rule_cache.glob("*.json")):
            if rfile.name == "_index.json":
                continue
            r = _kibana.read_cache(rfile)
            ref, items = rule_exceptions.fetch_for_rule(kb, auth, r)
            if ref and items:
                payload = {"rule_id": r.get("rule_id"), "rule_name": r.get("name"),
                           "list_ref": ref, "items": items}
                _kibana.write_cache(rxc / f"{slug(r.get('rule_id') or '')}.json", payload)
                index.append(r.get("rule_id"))
        _kibana.write_cache(rxc / "_index.json", index)
        print(f"    ✓ rule_exceptions: {len(index)} rule-default lists with items cached")

    return PROJECT_ROOT / ".import-cache" / dump_id


# ---------------------------------------------------------------------------
# Render phase
# ---------------------------------------------------------------------------
def _load_cache(dump_id: str, namespace: str) -> Iterable[dict]:
    d = PROJECT_ROOT / ".import-cache" / dump_id / namespace
    if not d.exists():
        return
    for f in sorted(d.glob("*.json")):
        if f.name == "_index.json":
            continue
        yield _kibana.read_cache(f)


def render(dump_id: str, space_id: str, targets: set[str], dry_run: bool) -> dict:
    """Render .tf files + return summary including import blocks/cmds."""
    summary: dict = {
        "rules": [],
        "exception_lists": [],
        "rule_exceptions": [],
        "import_blocks": [],
        "import_cmds": [],
    }

    # ---- rules ------------------------------------------------------------
    rule_module_index: dict[str, str] = {}  # rule_id → module_name
    if "rules" in targets:
        taken = rules.existing_module_names(CUSTOM_RULES_DIR)
        idx = rules.next_index(CUSTOM_RULES_DIR)
        for r in _load_cache(dump_id, "rules"):
            base = slug(r.get("name", "imported_rule"))
            mod = base
            n = 2
            while mod in taken:
                mod = f"{base}_{n}"; n += 1
            taken.add(mod)
            fname = rules.filename_for(r, idx)
            tf = rules.render_tf(r, mod)
            target = CUSTOM_RULES_DIR / fname
            summary["rules"].append({"file": str(target.relative_to(PROJECT_ROOT)),
                                     "module": mod, "rule_id": r.get("rule_id")})
            kid = r.get("id", "")
            summary["import_blocks"].append(
                rules.import_block("custom_rules", mod, kid, space_id)
            )
            summary["import_cmds"].append(
                f"terraform import 'module.custom_rules.module.{mod}.{rules.RESOURCE_ADDR}' "
                f"'{space_id}/{kid}'"
            )
            rule_module_index[r.get("rule_id", "")] = mod
            if not dry_run:
                target.write_text(tf)
            idx += 1

    # ---- shared exception lists ------------------------------------------
    if "exception_lists" in targets:
        taken = exception_lists.existing_module_names(EXCEPTIONS_DIR)
        idx = exception_lists.next_index(EXCEPTIONS_DIR)
        for payload in _load_cache(dump_id, "exception_lists"):
            lst = payload["list"]
            items = payload.get("items", [])
            mod = exception_lists.module_name_for(lst, taken)
            taken.add(mod)
            fname = exception_lists.filename_for(lst, idx)
            tf = exception_lists.render_tf(lst, items, mod)
            target = EXCEPTIONS_DIR / fname
            summary["exception_lists"].append({"file": str(target.relative_to(PROJECT_ROOT)),
                                               "module": mod, "list_id": lst.get("list_id")})
            kid = lst.get("id", "")
            summary["import_blocks"].append(
                exception_lists.import_blocks("exceptions", mod, kid, space_id, items)
            )
            for it in items:
                if it.get("id") and it.get("item_id"):
                    summary["import_cmds"].append(
                        f"terraform import "
                        f"'module.exceptions.module.{mod}.{exception_lists.ITEM_RESOURCE_ADDR}[\"{it['item_id']}\"]' "
                        f"'{space_id}/{it['id']}'"
                    )
            summary["import_cmds"].append(
                f"terraform import 'module.exceptions.module.{mod}.{exception_lists.LIST_RESOURCE_ADDR}' "
                f"'{space_id}/{kid}'"
            )
            if not dry_run:
                target.write_text(tf)
            idx += 1

    # ---- rule-scoped exceptions ------------------------------------------
    if "rule_exceptions" in targets:
        idx = rule_exceptions.next_index(RULE_EXCEPTIONS_DIR)
        for payload in _load_cache(dump_id, "rule_exceptions"):
            rule_id = payload.get("rule_id", "")
            rule_name = payload.get("rule_name", rule_id)
            items = payload.get("items", [])
            mod = rule_module_index.get(rule_id) or slug(rule_name)
            fname = rule_exceptions.filename_for(mod, idx)
            tf = rule_exceptions.render_tf(mod, rule_name, items)
            target = RULE_EXCEPTIONS_DIR / fname
            summary["rule_exceptions"].append({"file": str(target.relative_to(PROJECT_ROOT)),
                                               "module": f"{mod}_extras",
                                               "rule_id": rule_id})
            summary["import_blocks"].append(
                rule_exceptions.import_blocks("rule_exceptions", mod, items, space_id)
            )
            for it in items:
                if it.get("id") and it.get("item_id"):
                    summary["import_cmds"].append(
                        f"terraform import "
                        f"'module.rule_exceptions.module.{mod}_extras.{rule_exceptions.ITEM_RESOURCE_ADDR}[\"{it['item_id']}\"]' "
                        f"'{space_id}/{it['id']}'"
                    )
            if not dry_run:
                target.write_text(tf)
            idx += 1

    return summary


def write_import_artifacts(summary: dict, dry_run: bool) -> None:
    """Drop imports.tf + import.sh next to terraform/ for one-shot adoption."""
    blocks = "\n".join(b for b in summary["import_blocks"] if b)
    header = (
        "# =============================================================================\n"
        "# imports.tf — generated by scripts/bulk_import.py\n"
        "# =============================================================================\n"
        "# Terraform 1.5+ import blocks for the brownfield migration. After the\n"
        "# first successful `terraform apply` hydrates state, DELETE THIS FILE.\n"
        "# Do NOT keep import blocks in version control long-term.\n"
        "# =============================================================================\n\n"
    )
    imports_tf = TF_DIR / "imports.tf"
    import_sh = PROJECT_ROOT / "scripts" / "import.generated.sh"
    sh_body = "#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/../terraform\"\n\n" + \
              "\n".join(summary["import_cmds"]) + "\n"

    if dry_run:
        print("\n  (dry-run) would write:")
        print(f"    - {imports_tf.relative_to(PROJECT_ROOT)} ({len(summary['import_blocks'])} blocks)")
        print(f"    - {import_sh.relative_to(PROJECT_ROOT)} ({len(summary['import_cmds'])} commands)")
        return

    imports_tf.write_text(header + blocks)
    import_sh.write_text(sh_body)
    import_sh.chmod(0o755)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    args = parse_args()
    targets = parse_targets(args.only)

    if not args.from_cache:
        kb = _kibana.resolve_endpoint(args.kibana_url)
        auth = _kibana.auth_header()
        dump_dir = dump(kb, auth, args.dump_id, targets)
        if args.dump_only:
            print(f"\n  ✓ dump complete: {dump_dir.relative_to(PROJECT_ROOT)}\n")
            return 0
        dump_id = args.dump_id
    else:
        dump_id = args.from_cache
        if not (PROJECT_ROOT / ".import-cache" / dump_id).exists():
            print(f"  ✗ no cache at .import-cache/{dump_id}", file=sys.stderr)
            return 1

    summary = render(dump_id, args.space_id, targets, args.dry_run)
    write_import_artifacts(summary, args.dry_run)

    print("\n  Summary")
    print("  -------")
    for key in ("rules", "exception_lists", "rule_exceptions"):
        if key in targets:
            print(f"    {key:<18} {len(summary[key]):>4} resources")
    print(f"    import blocks      {len(summary['import_blocks']):>4}")
    print(f"    import commands    {len(summary['import_cmds']):>4}")

    print(
        "\n  Next steps:\n"
        "    1. Review the generated .tf files; adjust tags / Team: prefix as needed.\n"
        "    2. Update terraform/custom_rules/outputs.tf, terraform/exceptions/outputs.tf,\n"
        "       and terraform/rule_exceptions/outputs.tf to register the new modules.\n"
        "    3. cd terraform && terraform init && terraform plan\n"
        "       → plan should show ONLY the import blocks landing as no-ops.\n"
        "    4. terraform apply (Phase 1 in IMPLEMENTATION_STRATEGY.md).\n"
        "    5. Re-run plan — it MUST be empty. Generator drift = bug, fix and regenerate.\n"
        "    6. Once apply is green, DELETE terraform/imports.tf.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
