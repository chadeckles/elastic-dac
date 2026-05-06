# =============================================================================
# Importer renderer tests — bulk_import HCL output stability
# =============================================================================
# These tests exercise scripts/importers/{rules,exception_lists,
# rule_exceptions}.py against a small set of fixture JSON files and assert:
#
#   1. The renderer doesn't crash on representative shapes (query, threshold,
#      eql, threat_match rules; shared exception lists with mixed entry types).
#   2. The output parses cleanly with python-hcl2 — same parser the existing
#      tests/test_rules.py uses to validate rendered .tf files.
#   3. Each rule type's required output fields are present.
#   4. The renderer's import {} block addresses match the resource addresses
#      the runbook documents.
#   5. Unsupported entry types (currently `list`) emit a TODO comment so plan
#      surfaces them instead of silently dropping them.
#
# These are NOT byte-for-byte snapshot tests — that would be too brittle as we
# tweak HCL formatting. They're shape tests: "did the field land at all".
# =============================================================================

import io
import json
import sys
from pathlib import Path

import hcl2
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Importers live under scripts/, which isn't a regular package — make it one.
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from importers import exception_lists, rule_exceptions, rules  # noqa: E402


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _strip_hcl_quotes(val):
    if isinstance(val, str) and len(val) >= 2 and val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    return val


def _clean(obj):
    """Recursively strip the extra quotes python-hcl2 wraps around strings."""
    if isinstance(obj, dict):
        return {_strip_hcl_quotes(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return _strip_hcl_quotes(obj)


def _parse_module(text: str, module_name: str) -> dict:
    """Parse rendered HCL and return the cleaned body of the named module."""
    parsed = hcl2.load(io.StringIO(text))
    for block in parsed.get("module", []):
        cleaned = _clean(block)
        if module_name in cleaned:
            return cleaned[module_name]
    raise AssertionError(
        f"module {module_name!r} not found; got: {list(_clean(b).keys() for b in parsed.get('module', []))}"
    )


# ---------------------------------------------------------------------------
# rules.render_tf — one test per rule type
# ---------------------------------------------------------------------------
class TestRenderRules:
    def test_query_rule_round_trips_metadata(self):
        rule = _load_fixture("rule_query.json")
        out = rules.render_tf(rule, "fixture_query")

        # Parses as valid HCL.
        mod = _parse_module(out, "fixture_query")

        # Required fields present.
        for f in ("name", "description", "type", "severity", "risk_score",
                  "rule_id", "tags", "from", "to", "interval", "max_signals"):
            assert f in mod, f"missing {f} in rendered query rule"

        # Triage / metadata passthroughs that previously dropped silently.
        for f in ("note", "setup", "false_positives", "references",
                  "author", "license", "rule_version"):
            assert f in mod, f"importer dropped optional field {f}"

        # MITRE simplified shape preferred over verbose threat.
        assert "mitre_attack" in mod
        assert "exceptions_list" in mod
        assert "alert_suppression" in mod

        # Team tag preserved (or auto-stamped Team: Imported if missing).
        tags = mod["tags"]
        assert any(t.startswith("Team:") for t in tags), tags

    def test_query_rule_alert_suppression_dict_duration(self):
        """Kibana sometimes returns duration as {value, unit}; make sure we
        flatten it to '5m' style."""
        rule = _load_fixture("rule_query.json")
        out = rules.render_tf(rule, "fixture_query")
        assert 'duration = "5m"' in out

    def test_threshold_rule_renders_threshold_block(self):
        rule = _load_fixture("rule_threshold.json")
        out = rules.render_tf(rule, "fixture_threshold")
        mod = _parse_module(out, "fixture_threshold")
        assert "threshold" in mod
        # python-hcl2 returns the threshold object as a dict.
        thr = mod["threshold"]
        assert thr["value"] == 10
        # field is rendered as a list.
        assert "source.ip" in thr["field"]

    def test_eql_rule_renders_timestamp_and_timeline(self):
        rule = _load_fixture("rule_eql.json")
        out = rules.render_tf(rule, "fixture_eql")
        mod = _parse_module(out, "fixture_eql")
        assert mod["type"] == "eql"
        assert mod["language"] == "eql"
        assert mod["timestamp_override"] == "event.ingested"
        assert mod["timeline_id"] == "tl-eql-default"
        assert mod["timeline_title"] == "EQL default timeline"

    def test_threat_match_rule_renders_threat_fields(self):
        rule = _load_fixture("rule_threat_match.json")
        out = rules.render_tf(rule, "fixture_threat_match")
        mod = _parse_module(out, "fixture_threat_match")
        assert mod["type"] == "threat_match"
        assert "threatintel-*" in mod["threat_index"]
        assert mod["threat_query"] == "*"
        assert mod["threat_indicator_path"] == "threat.indicator"

    def test_team_tag_auto_stamped_when_missing(self):
        rule = _load_fixture("rule_threshold.json")  # no Team: tag in fixture
        out = rules.render_tf(rule, "fixture_threshold_team")
        assert "Team: Imported" in out

    def test_import_block_address_matches_runbook(self):
        rule = _load_fixture("rule_query.json")
        block = rules.import_block("custom_rules", "fixture_query",
                                   rule["id"], "default")
        assert "module.custom_rules.module.fixture_query" in block
        assert "elasticstack_kibana_security_detection_rule.this" in block
        assert f'"default/{rule["id"]}"' in block


# ---------------------------------------------------------------------------
# exception_lists.render_tf — items, entry types, list-operator warning
# ---------------------------------------------------------------------------
class TestRenderExceptionLists:
    def test_shared_list_renders_items_and_flags_list_operator(self):
        payload = _load_fixture("exception_list_shared.json")
        out = exception_lists.render_tf(payload["list"], payload["items"],
                                        "fixture_shared")
        mod = _parse_module(out, "fixture_shared")
        assert mod["list_id"] == "fixture-shared-list"
        assert mod["type"] == "detection"

        items = mod["items"]
        # All three items render; the third (list-operator) keeps its shell
        # but its entries are emitted as a TODO comment so reviewers see it
        # rather than having it silently disappear.
        assert len(items) == 3
        item_ids = [i["item_id"] for i in items]
        assert "fixture-item-trusted-host" in item_ids
        assert "fixture-item-allowlist-ips" in item_ids
        assert "fixture-item-list-operator" in item_ids

        list_op_item = next(i for i in items
                            if i["item_id"] == "fixture-item-list-operator")
        assert list_op_item["entries"] == [], (
            "list-operator entry should be commented out, leaving empty entries"
        )

        # match → value
        host = next(i for i in items if i["item_id"] == "fixture-item-trusted-host")
        assert host["entries"][0]["field"] == "host.name"
        assert host["entries"][0]["value"] == "scanner-01"

        # match_any → values
        ips = next(i for i in items if i["item_id"] == "fixture-item-allowlist-ips")
        assert ips["entries"][0]["values"] == ["10.0.0.1", "10.0.0.2"]

        # list-operator entry surfaced as comment for reviewer attention.
        assert "TODO: list-operator entry not yet supported" in out
        assert "user-allowlist" in out

    def test_exception_list_import_blocks_use_item_id_keys(self):
        payload = _load_fixture("exception_list_shared.json")
        blocks = exception_lists.import_blocks(
            "exceptions", "fixture_shared",
            payload["list"]["id"], "default", payload["items"]
        )
        # The list itself + 3 items (we don't filter list-op items here, the
        # `list_id`+`id` presence check inside the function does).
        assert "elasticstack_kibana_security_exception_list.this" in blocks
        assert (
            'elasticstack_kibana_security_exception_item.this'
            '["fixture-item-trusted-host"]' in blocks
        )

    def test_exception_list_skips_endpoint_types(self):
        endpoint_list = {"type": "endpoint"}
        assert not exception_lists.is_shared_candidate(endpoint_list)

    def test_exception_list_skips_rule_default_types(self):
        rd = {"type": "rule_default"}
        assert not exception_lists.is_shared_candidate(rd)


# ---------------------------------------------------------------------------
# rule_exceptions.render_tf — uses the rule's _extras module pattern
# ---------------------------------------------------------------------------
class TestRenderRuleExceptions:
    def test_rule_exceptions_module_address_uses_extras_suffix(self):
        items = [{
            "id": "iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii",
            "item_id": "tune-1",
            "name": "Tune one",
            "description": "Tuning item.",
            "tags": [],
            "entries": [
                {"field": "host.name", "type": "match", "operator": "included", "value": "x"}
            ],
        }]
        out = rule_exceptions.render_tf("fixture_query", "Fixture Query Rule", items)
        assert 'module "fixture_query_extras"' in out
        assert 'var.rule_default_lists["fixture_query"]' in out

        blocks = rule_exceptions.import_blocks(
            "rule_exceptions", "fixture_query", items, "default"
        )
        assert "module.rule_exceptions.module.fixture_query_extras" in blocks
        assert 'elasticstack_kibana_security_exception_item.this["tune-1"]' in blocks


# ---------------------------------------------------------------------------
# regenerate_outputs — wiring stays in lockstep with on-disk modules
# ---------------------------------------------------------------------------
class TestOutputsRegeneration:
    def test_outputs_render_includes_all_modules(self, tmp_path, monkeypatch):
        """Render outputs.tf for a synthetic directory containing two modules."""
        # Minimal stub directory with two rule modules.
        d = tmp_path / "custom_rules"
        d.mkdir()
        (d / "001_alpha.tf").write_text('module "alpha" { source = "x" }\n')
        (d / "002_beta.tf").write_text('module "beta" { source = "y" }\n')
        (d / "_providers.tf").write_text('module "should_be_skipped" { source = "z" }\n')

        # Import bulk_import via path; reuse its internal helpers.
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import bulk_import  # noqa: E402

        names = bulk_import._aggregate_existing_module_names(d)
        assert names == ["alpha", "beta"]
        assert "should_be_skipped" not in names

        body = bulk_import._render_outputs_custom_rules(names)
        # Both rule_ids and rule_default_exception_list_ids outputs include both modules.
        assert "alpha = module.alpha.rule_id" in body
        assert "beta  = module.beta.rule_id" in body
        assert "alpha = module.alpha.rule_default_exception_list_id" in body
        assert "beta  = module.beta.rule_default_exception_list_id" in body
