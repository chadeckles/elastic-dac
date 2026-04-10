# =============================================================================
# Rule Unit Tests — Detection as Code
# =============================================================================
# Pytest-based validation for custom detection rules and exception lists.
# Parses the individual .tf files in custom_rules/ and exceptions/ to
# validate structure *before* terraform plan/apply.
#
# The tests extract module call arguments from HCL2-parsed data, which
# mirrors the module variable interface in modules/detection_rule/.
#
# Reference:
#   https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features
#
# Run:
#   pytest -v
# =============================================================================

import re
from pathlib import Path

import hcl2
import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
TF_DIR = Path(__file__).resolve().parent.parent / "terraform"
CUSTOM_RULES_DIR = TF_DIR / "custom_rules"
EXCEPTIONS_DIR = TF_DIR / "exceptions"


# ---------------------------------------------------------------------------
# HCL2 helpers
# ---------------------------------------------------------------------------
def _strip_hcl_quotes(val):
    """python-hcl2 wraps bare strings in extra quotes — strip them."""
    if isinstance(val, str) and len(val) >= 2 and val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    return val


def _clean(obj):
    """Recursively strip HCL2 extra quotes from parsed data."""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return _strip_hcl_quotes(obj)


def _load_modules_from_dir(tf_dir: Path) -> dict:
    """Parse all .tf files in a directory and return module blocks.

    Returns a dict keyed by module name, value is the module's arguments.
    Skips files starting with _ (providers, templates).
    """
    modules: dict = {}
    for tf_file in sorted(tf_dir.glob("*.tf")):
        if tf_file.name.startswith("_"):
            continue
        with tf_file.open() as f:
            try:
                parsed = hcl2.load(f)
            except Exception:
                continue
        for mod_block in parsed.get("module", []):
            for mod_name, mod_body in mod_block.items():
                modules[mod_name] = _clean(mod_body)
    return modules


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def all_rules() -> dict:
    """Return dict of module_name → module args for every custom rule."""
    return _load_modules_from_dir(CUSTOM_RULES_DIR)


@pytest.fixture(scope="session")
def all_exception_lists() -> dict:
    """Return dict of module_name → module args for every exception list."""
    return _load_modules_from_dir(EXCEPTIONS_DIR)


# =============================================================================
# Test: Required fields are present
# =============================================================================
class TestRequiredFields:
    """Every custom rule module must pass the required variables."""

    REQUIRED_FIELDS = {"name", "description", "type", "severity", "risk_score", "tags", "threat"}

    def test_rules_have_required_fields(self, all_rules: dict):
        assert len(all_rules) > 0, "No custom rule .tf files found in custom_rules/"
        for key, rule in all_rules.items():
            missing = self.REQUIRED_FIELDS - set(rule.keys())
            assert not missing, (
                f"Rule '{key}' is missing required fields: {missing}"
            )


# =============================================================================
# Test: Team tag enforcement (per DaC guide recommendation)
# =============================================================================
class TestTeamTag:
    """Every custom rule must have a 'Team: <team_name>' tag.

    Reference:
      https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features
    """

    TEAM_TAG_PATTERN = re.compile(r"^Team:\s+\S+")

    def test_rules_have_team_tag(self, all_rules: dict):
        for key, rule in all_rules.items():
            tags = rule.get("tags", [])
            has_team = any(self.TEAM_TAG_PATTERN.match(t) for t in tags)
            assert has_team, (
                f"Rule '{key}' does not have a 'Team: <team_name>' tag. "
                "All custom rules must include a team tag for SOC routing."
            )


# =============================================================================
# Test: MITRE ATT&CK mapping present
# =============================================================================
class TestMitreMapping:
    """Every custom rule should map to at least one MITRE ATT&CK tactic."""

    def test_rules_have_threat_mapping(self, all_rules: dict):
        for key, rule in all_rules.items():
            threat = rule.get("threat", [])
            assert len(threat) > 0, (
                f"Rule '{key}' has no MITRE ATT&CK threat mapping."
            )

    def test_threat_has_valid_tactic(self, all_rules: dict):
        for key, rule in all_rules.items():
            for i, t in enumerate(rule.get("threat", [])):
                tactic = t.get("tactic", {})
                assert "id" in tactic, (
                    f"Rule '{key}' threat[{i}].tactic missing 'id'."
                )
                assert tactic["id"].startswith("TA"), (
                    f"Rule '{key}' threat[{i}].tactic.id '{tactic['id']}' "
                    "does not look like a valid MITRE tactic ID."
                )


# =============================================================================
# Test: Risk score is within valid range
# =============================================================================
class TestRiskScore:
    """Risk scores must be between 0 and 100."""

    def test_risk_score_range(self, all_rules: dict):
        for key, rule in all_rules.items():
            score = rule.get("risk_score", 0)
            assert 0 <= score <= 100, (
                f"Rule '{key}' has risk_score={score}, must be 0–100."
            )


# =============================================================================
# Test: Severity is a valid value
# =============================================================================
class TestSeverity:
    """Severity must be one of: low, medium, high, critical."""

    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    def test_severity_value(self, all_rules: dict):
        for key, rule in all_rules.items():
            severity = rule.get("severity", "medium")
            assert severity in self.VALID_SEVERITIES, (
                f"Rule '{key}' has severity='{severity}', "
                f"must be one of {self.VALID_SEVERITIES}."
            )


# =============================================================================
# Test: Rule type is valid
# =============================================================================
class TestRuleType:
    """Type must be a supported Elastic detection rule type."""

    VALID_TYPES = {
        "query", "eql", "esql", "machine_learning",
        "new_terms", "saved_query", "threat_match", "threshold",
    }

    def test_type_value(self, all_rules: dict):
        for key, rule in all_rules.items():
            rtype = rule.get("type")
            assert rtype in self.VALID_TYPES, (
                f"Rule '{key}' has type='{rtype}', "
                f"must be one of {self.VALID_TYPES}."
            )


# =============================================================================
# Test: Query-based rules have a query
# =============================================================================
class TestQueryPresence:
    """Rules that need a query must supply one."""

    QUERY_TYPES = {"query", "eql", "esql", "threshold", "new_terms", "threat_match"}

    def test_query_based_rules_have_query(self, all_rules: dict):
        for key, rule in all_rules.items():
            if rule.get("type") in self.QUERY_TYPES:
                assert rule.get("query"), (
                    f"Rule '{key}' is type '{rule['type']}' but has no query."
                )


# =============================================================================
# Test: Exception list structure
# =============================================================================
class TestExceptionLists:
    """Validate exception list definitions have required fields."""

    def test_lists_have_required_fields(self, all_exception_lists: dict):
        assert len(all_exception_lists) > 0, "No exception .tf files found in exceptions/"
        for key, exc_list in all_exception_lists.items():
            assert "list_id" in exc_list, f"Exception list '{key}' missing 'list_id'."
            assert "name" in exc_list, f"Exception list '{key}' missing 'name'."
            assert "description" in exc_list, f"Exception list '{key}' missing 'description'."

    def test_items_have_entries(self, all_exception_lists: dict):
        for list_key, exc_list in all_exception_lists.items():
            for i, item in enumerate(exc_list.get("items", [])):
                assert "entries" in item and len(item["entries"]) > 0, (
                    f"Exception item #{i} in '{list_key}' has no entries."
                )

    def test_items_have_required_fields(self, all_exception_lists: dict):
        for list_key, exc_list in all_exception_lists.items():
            for i, item in enumerate(exc_list.get("items", [])):
                assert "name" in item, (
                    f"Exception item #{i} in '{list_key}' missing 'name'."
                )
                assert "description" in item, (
                    f"Exception item #{i} in '{list_key}' missing 'description'."
                )
