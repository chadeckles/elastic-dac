#!/usr/bin/env python3
"""
sync_upstream_rules.py

Syncs with Elastic's detection-rules repository and generates a changelog
of new, modified, and removed detection rules since the last sync.

This script is designed to run:
  - Weekly via GitHub Actions (see .github/workflows/sync-detection-rules.yml)
  - Locally via `make sync-upstream`

Usage:
    python3 scripts/sync_upstream_rules.py [OPTIONS]

Options:
    --repo-dir PATH       Where to clone detection-rules (default: /tmp/elastic-detection-rules)
    --project-root PATH   Root of this project (default: auto-detected via git)
    --dry-run             Generate changelog but don't update the tracking file
    --first-sync-full     On first sync, catalog all rules (default: baseline only)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# TOML parsing — works across Python 3.9+ with graceful fallbacks
# ---------------------------------------------------------------------------
_toml_parser = None

try:
    import tomllib as _toml_parser          # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as _toml_parser        # pip install tomli
    except ModuleNotFoundError:
        pass                                # Falls back to regex extraction


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
UPSTREAM_REPO = "https://github.com/elastic/detection-rules.git"
UPSTREAM_BRANCH = "main"
SYNC_FILE = ".detection-rules-sync"
CHANGELOG_FILE = "UPSTREAM_CHANGELOG.md"
# Rule TOML files live under these directories in the upstream repo
RULES_DIRS = ["rules", "rules_building_block"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run(cmd, cwd=None, check=True):
    """Run a shell command and return stdout."""
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, check=check
    )
    return result.stdout.strip()


def log(msg):
    """Print with a prefix for visibility."""
    print(f"  {msg}")


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------
def clone_or_fetch(repo_dir: Path) -> str:
    """Clone (blobless) or fetch the upstream repo.  Returns HEAD SHA."""
    if (repo_dir / ".git").exists():
        print(f"→ Fetching latest from {UPSTREAM_REPO}…")
        run(["git", "fetch", "origin", UPSTREAM_BRANCH], cwd=repo_dir)
        run(["git", "reset", "--hard", f"origin/{UPSTREAM_BRANCH}"], cwd=repo_dir)
    else:
        print(f"→ Cloning {UPSTREAM_REPO} (blobless)…")
        run([
            "git", "clone",
            "--filter=blob:none",       # Download commit graph; blobs on demand
            "--branch", UPSTREAM_BRANCH,
            UPSTREAM_REPO,
            str(repo_dir),
        ])

    head_sha = run(["git", "rev-parse", "HEAD"], cwd=repo_dir)
    log(f"Upstream HEAD: {head_sha[:12]}")
    return head_sha


# ---------------------------------------------------------------------------
# Sync state management
# ---------------------------------------------------------------------------
def read_sync_state(project_root: Path) -> dict:
    """Read the tracking file.  Returns {} on first run."""
    path = project_root / SYNC_FILE
    if path.exists():
        return json.loads(path.read_text())
    return {}


def write_sync_state(project_root: Path, sha: str, stats: dict):
    """Persist the latest sync SHA and metadata."""
    path = project_root / SYNC_FILE
    path.write_text(json.dumps({
        "last_sha": sha,
        "last_sync": datetime.now(timezone.utc).isoformat(),
        "upstream_repo": UPSTREAM_REPO,
        "stats": stats,
    }, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Diff detection
# ---------------------------------------------------------------------------
def get_changed_files(repo_dir: Path, old_sha: str | None, new_sha: str) -> dict:
    """Return {added: [], modified: [], deleted: []} for rule TOML files."""
    changes = {"added": [], "modified": [], "deleted": []}
    paths_arg = ["--"] + RULES_DIRS

    if old_sha is None:
        # First sync — list every TOML under RULES_DIRS
        for rules_dir in RULES_DIRS:
            try:
                output = run(
                    ["git", "ls-tree", "-r", "--name-only", new_sha, "--", rules_dir],
                    cwd=repo_dir,
                )
            except subprocess.CalledProcessError:
                continue
            if output:
                changes["added"].extend(
                    f for f in output.splitlines() if f.endswith(".toml")
                )
        return changes

    # Ensure we have enough history to reach old_sha
    try:
        run(["git", "cat-file", "-t", old_sha], cwd=repo_dir)
    except subprocess.CalledProcessError:
        log("Deepening clone to reach previous sync point…")
        run(["git", "fetch", "--unshallow"], cwd=repo_dir, check=False)
        run(["git", "fetch", "origin", UPSTREAM_BRANCH], cwd=repo_dir)

    try:
        output = run(
            ["git", "diff", "--name-status", old_sha, new_sha] + paths_arg,
            cwd=repo_dir,
        )
    except subprocess.CalledProcessError:
        log("⚠  Could not diff; treating as full re-scan")
        return get_changed_files(repo_dir, None, new_sha)

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0][0]       # A, M, D, R (rename)
        filepath = parts[-1]       # Last element handles renames

        if not filepath.endswith(".toml"):
            continue

        if status == "A":
            changes["added"].append(filepath)
        elif status == "M":
            changes["modified"].append(filepath)
        elif status == "D":
            changes["deleted"].append(filepath)
        elif status == "R":
            changes["deleted"].append(parts[1])   # Old name
            changes["added"].append(parts[2])      # New name

    return changes


# ---------------------------------------------------------------------------
# TOML rule metadata extraction
# ---------------------------------------------------------------------------
def _parse_toml(filepath: Path) -> dict | None:
    """Parse a TOML file; returns raw dict or None."""
    if not filepath.exists():
        return None

    if _toml_parser is not None:
        try:
            # tomllib / tomli use binary mode
            if hasattr(_toml_parser, "load"):
                with open(filepath, "rb") as f:
                    return _toml_parser.load(f)
            return _toml_parser.loads(filepath.read_text())
        except Exception:
            pass

    # Fallback — regex extraction (no dependency needed)
    return None


def _regex_extract(filepath: Path) -> dict:
    """Best-effort metadata extraction without a TOML parser."""
    text = filepath.read_text(errors="replace")
    def _get(key):
        m = re.search(rf'^{key}\s*=\s*"(.+?)"', text, re.MULTILINE)
        return m.group(1) if m else None
    return {
        "name": _get("name") or filepath.name,
        "description": (_get("description") or "")[:120],
        "severity": _get("severity") or "—",
        "type": _get("type") or "—",
        "risk_score": _get("risk_score") or "—",
    }


def extract_rule_metadata(repo_dir: Path, filepath: str) -> dict:
    """Return a normalised metadata dict for a single TOML rule file."""
    full_path = repo_dir / filepath
    base = {
        "name": filepath,
        "description": "",
        "severity": "—",
        "type": "—",
        "risk_score": "—",
        "tags": [],
        "threat": [],
        "path": filepath,
    }

    parsed = _parse_toml(full_path)
    if parsed:
        rule = parsed.get("rule", {})
        base.update({
            "name": rule.get("name", filepath),
            "description": (rule.get("description", "") or "")[:120],
            "severity": rule.get("severity", "—"),
            "type": rule.get("type", "—"),
            "risk_score": rule.get("risk_score", "—"),
            "tags": rule.get("tags", []),
            "threat": rule.get("threat", []),
        })
    else:
        # Regex fallback
        base.update(_regex_extract(full_path) if full_path.exists() else {})

    return base


# ---------------------------------------------------------------------------
# MITRE tactic helper
# ---------------------------------------------------------------------------
def _get_tactics(meta: dict) -> str:
    """Extract a comma-separated tactic list from threat mapping."""
    tactics = []
    for entry in meta.get("threat", []):
        tactic = entry.get("tactic", {})
        name = tactic.get("name")
        if name:
            tactics.append(name)
    return ", ".join(tactics) if tactics else "—"


# ---------------------------------------------------------------------------
# Changelog generation
# ---------------------------------------------------------------------------
def generate_changelog_entry(
    changes: dict,
    rules_meta: dict,
    old_sha: str | None,
    new_sha: str,
) -> str:
    """Build a Markdown changelog entry."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    short_new = new_sha[:12]
    short_old = old_sha[:12] if old_sha else "initial"

    total = sum(len(v) for v in changes.values())

    lines = [
        f"## {now} — Upstream Sync `{short_old}..{short_new}`\n",
        f"**Source**: [`elastic/detection-rules@{short_new}`]"
        f"(https://github.com/elastic/detection-rules/commit/{new_sha})\n",
        f"**Summary**: {total} rule file(s) changed — "
        f"{len(changes['added'])} added, "
        f"{len(changes['modified'])} modified, "
        f"{len(changes['deleted'])} removed\n",
    ]

    # ---- New rules ----------------------------------------------------------
    if changes["added"]:
        lines.append("### ➕ New Rules\n")
        lines.append("| Rule | Type | Severity | MITRE Tactic(s) | Path |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(changes["added"]):
            m = rules_meta.get(f, {})
            lines.append(
                f"| {m.get('name', f)} "
                f"| `{m.get('type', '—')}` "
                f"| {m.get('severity', '—')} "
                f"| {_get_tactics(m)} "
                f"| `{f}` |"
            )
        lines.append("")

    # ---- Modified rules -----------------------------------------------------
    if changes["modified"]:
        lines.append("### ✏️ Modified Rules\n")
        lines.append("| Rule | Type | Severity | MITRE Tactic(s) | Path |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(changes["modified"]):
            m = rules_meta.get(f, {})
            lines.append(
                f"| {m.get('name', f)} "
                f"| `{m.get('type', '—')}` "
                f"| {m.get('severity', '—')} "
                f"| {_get_tactics(m)} "
                f"| `{f}` |"
            )
        lines.append("")

    # ---- Removed rules ------------------------------------------------------
    if changes["deleted"]:
        lines.append("### ❌ Removed Rules\n")
        lines.append("| Path |")
        lines.append("|---|")
        for f in sorted(changes["deleted"]):
            lines.append(f"| `{f}` |")
        lines.append("")

    if total == 0:
        lines.append("_No rule changes detected since last sync._\n")

    lines.append("---\n")
    return "\n".join(lines)


def write_changelog(project_root: Path, entry: str):
    """Prepend a new entry to the changelog file (most-recent first)."""
    changelog = project_root / CHANGELOG_FILE

    header = (
        "# Upstream Detection Rules Changelog\n\n"
        "> Auto-generated by the weekly sync from "
        "[elastic/detection-rules](https://github.com/elastic/detection-rules).  \n"
        "> Each entry summarises rule additions, modifications, and removals "
        "since the previous sync.\n\n---\n\n"
    )

    if changelog.exists():
        existing = changelog.read_text()
        # Strip the existing header to avoid duplication
        marker = "---\n\n"
        idx = existing.find(marker, len("# Upstream"))
        if idx != -1:
            existing = existing[idx + len(marker):]
        content = header + entry + existing
    else:
        content = header + entry

    changelog.write_text(content)
    log(f"Changelog written: {CHANGELOG_FILE}")


# ---------------------------------------------------------------------------
# GitHub Actions outputs
# ---------------------------------------------------------------------------
def set_github_outputs(changes: dict, new_sha: str):
    """Write to $GITHUB_OUTPUT if running in Actions."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    total = sum(len(v) for v in changes.values())
    with open(output_file, "a") as f:
        f.write(f"changes_detected={'true' if total > 0 else 'false'}\n")
        f.write(f"total_changes={total}\n")
        f.write(f"added={len(changes['added'])}\n")
        f.write(f"modified={len(changes['modified'])}\n")
        f.write(f"deleted={len(changes['deleted'])}\n")
        f.write(f"upstream_sha={new_sha}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Sync upstream Elastic detection rules and generate a changelog."
    )
    parser.add_argument(
        "--repo-dir",
        default="/tmp/elastic-detection-rules",
        help="Local path to clone detection-rules into (default: /tmp/elastic-detection-rules)",
    )
    parser.add_argument(
        "--project-root",
        default=None,
        help="Root of the DaC project (default: auto-detect via git)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate changelog but don't update the tracking file",
    )
    parser.add_argument(
        "--first-sync-full",
        action="store_true",
        help="On first sync, catalog all rules instead of just establishing baseline",
    )
    args = parser.parse_args()

    repo_dir = Path(args.repo_dir)

    if args.project_root:
        project_root = Path(args.project_root)
    else:
        project_root = Path(run(["git", "rev-parse", "--show-toplevel"]))

    print(f"Project root : {project_root}")
    print(f"Clone target : {repo_dir}\n")

    # 1. Clone or fetch upstream
    new_sha = clone_or_fetch(repo_dir)

    # 2. Read last sync state
    state = read_sync_state(project_root)
    old_sha = state.get("last_sha")

    if old_sha:
        log(f"Last sync SHA: {old_sha[:12]}")
    else:
        log("First sync — establishing baseline")

    if old_sha == new_sha:
        print("\n✅ Already up to date — no changes since last sync.")
        set_github_outputs({"added": [], "modified": [], "deleted": []}, new_sha)
        return 0

    # 3. Detect changes
    print("\n→ Analysing changes…")
    is_first_sync = old_sha is None

    if is_first_sync and not args.first_sync_full:
        # Don't generate a massive changelog on first run; just save the baseline
        log("Baseline mode — recording SHA without cataloging all rules")
        stats = {"added": 0, "modified": 0, "deleted": 0, "baseline": True}

        entry = generate_changelog_entry(
            {"added": [], "modified": [], "deleted": []},
            {},
            None,
            new_sha,
        )
        # Override with a friendlier message
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = (
            f"## {now} — Baseline Established `{new_sha[:12]}`\n\n"
            f"**Source**: [`elastic/detection-rules@{new_sha[:12]}`]"
            f"(https://github.com/elastic/detection-rules/commit/{new_sha})\n\n"
            "Initial sync — baseline SHA recorded.  Future syncs will report "
            "changes relative to this point.\n\n---\n\n"
        )
        write_changelog(project_root, entry)

        if not args.dry_run:
            write_sync_state(project_root, new_sha, stats)
            log(f"Tracking file saved: {SYNC_FILE}")

        set_github_outputs({"added": [], "modified": [], "deleted": []}, new_sha)
        print("\n✅ Baseline established.  Next sync will detect changes.")
        return 0

    changes = get_changed_files(repo_dir, old_sha, new_sha)
    total = sum(len(v) for v in changes.values())

    log(f"Added    : {len(changes['added'])}")
    log(f"Modified : {len(changes['modified'])}")
    log(f"Deleted  : {len(changes['deleted'])}")

    # 4. Parse metadata for rich changelog
    if total > 0:
        print("\n→ Parsing rule metadata…")
        rules_meta = {}
        for f in changes["added"] + changes["modified"]:
            rules_meta[f] = extract_rule_metadata(repo_dir, f)
    else:
        rules_meta = {}

    # 5. Generate and write changelog
    entry = generate_changelog_entry(changes, rules_meta, old_sha, new_sha)
    write_changelog(project_root, entry)

    # 6. Update tracking file
    stats = {
        "added": len(changes["added"]),
        "modified": len(changes["modified"]),
        "deleted": len(changes["deleted"]),
    }
    if not args.dry_run:
        write_sync_state(project_root, new_sha, stats)
        log(f"Tracking file saved: {SYNC_FILE}")
    else:
        log(f"[DRY RUN] Would update {SYNC_FILE} → {new_sha[:12]}")

    # 7. GitHub Actions integration
    set_github_outputs(changes, new_sha)

    print(f"\n✅ Sync complete — {total} change(s) detected.")
    # Exit 2 when changes found (signals "has updates" to CI without being a failure)
    return 0 if total == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
