# Operations Runbook — Detection as Code

> Step-by-step playbooks for the day-to-day operations of this repo.
> Each step has a one-line "why" so you understand intent, not just commands.
>
> **Companion docs:** [README.md](README.md) · [IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md) · [.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md)
>
> **Three playbooks:**
> 1. [Brownfield import](#playbook-1--brownfield-import) — pull live Kibana into Terraform (one-time).
> 2. [Adopt a UI change](#playbook-2--adopt-a-ui-created-rule-or-exception) — analyst made it in Kibana, get it into code.
> 3. [Author a new rule in code](#playbook-3--author-a-net-new-rule-or-exception) — code-first, deploy via CI.

## Conventions

- `$` = laptop · `runner$` = GitLab runner host · `kibana$` = Kibana UI click.
- All paths are relative to the repo root. Placeholders look like `<this>`.

## Pre-flight (every session)

```sh
$ cd /path/to/elastic-dac
$ export KIBANA_ENDPOINT=https://<your-kb-host>:9243
$ export KIBANA_API_KEY=<encoded-api-key>
$ curl -sf -H "Authorization: ApiKey $KIBANA_API_KEY" \
    "$KIBANA_ENDPOINT/api/detection_engine/rules/_find?per_page=1" | head -c 200 && echo
```

If the `curl` fails, **stop** — every script depends on it. Common causes:
401 (key wrong/expired/wrong space), TLS error (cert trust), connection
refused (use `:9243`, not `:443`).

---

# Playbook 1 — Brownfield import

> **When:** exactly **once**, the first time a Kibana space is brought
> under Terraform.
> **Time:** 1–3 hours, mostly waiting on plan output.
> **Risk:** low if you honor the `0 to add, 0 to change, 0 to destroy`
> rule. The importer is read-only on Kibana; the only mutation is the
> final `terraform apply`.
> **Need:** [the 6 GitLab CI variables](README.md#cicd-pipeline) set, SSH
> on the runner (or Pattern B), and an API key with read on detection
> rules + exception lists.

### 1. Snapshot Kibana for rollback

```
kibana$ Stack Management → Saved Objects → Export
        Filter: rule, exception-list, exception-list-agnostic → save .ndjson
```

Cheap insurance — re-importable via the same UI if something goes wrong.

### 2. Dump live Kibana to a local cache

```sh
$ make bulk-import-dump
$ DUMP=$(date +%F)
$ wc -l .import-cache/$DUMP/rules/*.json \
        .import-cache/$DUMP/exception_lists/*.json \
        .import-cache/$DUMP/rule_exceptions/*.json
```

The cache is gitignored so you can re-render as many times as you want
without re-hitting Kibana. **Red flags:** zero rules (API-key scope) or
10× the expected count (wrong space) — stop and verify.

### 3. Preview, then render

```sh
$ make bulk-import-diff       DUMP_ID=$DUMP   # in-memory diff, no writes
$ make bulk-import-from-cache DUMP_ID=$DUMP   # actually render
```

The render step writes:

- `.tf` files into [terraform/custom_rules/](terraform/custom_rules/), [terraform/exceptions/](terraform/exceptions/), [terraform/rule_exceptions/](terraform/rule_exceptions/) (committed).
- Regenerates the three `outputs.tf` files in lockstep — no manual editing.
- `terraform/imports.tf` (Terraform 1.5 `import {}` blocks) and `scripts/import.generated.sh` — both **gitignored**, one-shot.
- Auto-runs `terraform fmt -recursive` so output is CI-clean.

#### Fields the importer round-trips today

- **Common:** `name`, `description`, `type`, `severity`, `risk_score`,
  `query`, `language`, `from`, `to`, `interval`, `max_signals`, `index`,
  `tags`, `enabled`, `rule_id`, `note`, `setup`, `false_positives`,
  `references`, `author`, `license`, `version`, `building_block_type`,
  `timestamp_override`, `timeline_id`/`title`, `exceptions_list[]`,
  `alert_suppression`.
- **Type-specific:** `threshold`, `new_terms_fields` + `history_window_start`,
  `machine_learning_job_id` + `anomaly_threshold`, `threat_index` +
  `threat_query` + `threat_indicator_path`.
- **MITRE:** simplified `mitre_attack[]` preferred; falls back to verbose `threat[]`.

#### Known gaps (will plan as `1 to change` until fixed)

- `response_actions`, `investigation_fields`, `data_view_id` — banner-warned in the rendered .tf.
- `threat_match` rules' `threat_mapping` — module variable missing in [variables.tf](terraform/modules/detection_rule/variables.tf).
- Exception entries with the `list` operator — emitted as a `# TODO:` comment so reviewers see them; provider supports it but module schema doesn't yet.

### 4. Review

```sh
$ git status
$ git diff terraform/ | less
```

Spot-check: every rule has a `Team:` tag (importer stamps `Team: Imported`
if missing); MITRE IDs aren't blank; exception `entries` have valid
`field`/`type`/`operator`; index lists aren't truncated.

### 5. Open the validation MR

```sh
$ git checkout -b brownfield/initial-import
$ git add terraform/ && git commit -m "Phase 1: initial import of <space-id>"
$ git push origin brownfield/initial-import
```

> **The plan on this MR will say "create N resources."** Expected — the
> runner doesn't have `imports.tf` yet (gitignored). This MR exists only
> to confirm `pytest`/`fmt`/`validate` pass. **Do not merge yet.**

### 6. Run the import on the runner

This is the only step that mutates state.

#### Pattern A — SSH (recommended for first run)

```sh
$ scp terraform/imports.tf scripts/import.generated.sh <runner>:/tmp/
$ ssh <runner>

runner$ cd elastic-dac && git fetch && git checkout brownfield/initial-import
runner$ cp /tmp/imports.tf terraform/imports.tf
runner$ cd terraform
runner$ export AWS_DEFAULT_REGION=<region> TF_STATE_BUCKET=<bucket> \
               TF_STATE_KEY=<key> KIBANA_ENDPOINT=<url> KIBANA_API_KEY=<encoded>
runner$ terraform init \
          -backend-config="bucket=$TF_STATE_BUCKET" \
          -backend-config="key=$TF_STATE_KEY" \
          -backend-config="region=$AWS_DEFAULT_REGION" \
          -backend-config="use_lockfile=true" -backend-config="encrypt=true"
runner$ terraform plan
```

**Read carefully.** Plan must say `Plan: 0 to add, 0 to change, 0 to destroy`
followed by an "import" list. Anything else, **abort**:
- `1 to add` → resource missing in Kibana, or wrong space.
- `1 to change` → field rendered differently from live; fix the .tf, re-render.
- `1 to destroy` → **stop immediately**; do not apply.

If clean, apply and clean up:

```sh
runner$ terraform apply
runner$ rm imports.tf            # CRITICAL — one-shot directives
runner$ terraform plan           # MUST now show "No changes."
```

#### Pattern B — Manual CI job (no SSH)

Add a temporary manual-trigger `terraform:bulk-import` job to
[.gitlab-ci.yml](.gitlab-ci.yml) following [IMPLEMENTATION_STRATEGY.md §Phased Rollout](IMPLEMENTATION_STRATEGY.md#phased-rollout). Revert after the import. Riskier — don't wing it in the lab.

### 7. Final validation in CI

```sh
$ git commit --allow-empty -m "trigger CI re-plan after import" && git push
```

The MR's `terraform:plan` job must now show **"No changes."** Merge.

### 8. Stay in plan-only mode (Phase 2)

`TF_AUTO_APPLY` stays `"false"` for 2–3 weeks while the team validates
fidelity and the drift loop catches UI activity. See
[IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md) Phase 2.

---

# Playbook 2 — Adopt a UI-created rule or exception

> **When:** an analyst made (or modified) a rule/exception in the UI and
> you want it in code. The most common Phase 4 / steady-state flow.
> **Time:** 10–20 min per resource. **Risk:** very low.

You'll notice this when (a) nightly CI plan is non-empty, (b) someone
pings you, or (c) you start authoring something that already exists.

### 1. Identify

```sh
$ make list-rules                                          # browse
$ python3 scripts/import_gui_rule.py --list | grep -i <kw> # search
```

For exception lists, find the `list_id` in *Kibana → Security → Manage → Exception lists*.

### 2a. Single rule

```sh
$ python3 scripts/import_gui_rule.py --name "My New Rule"
# or:  --rule-id <uuid>
```

Generates one `.tf` under [terraform/custom_rules/](terraform/custom_rules/) and prints the
`terraform import` command for the runner.

### 2b. Exception list / rule-scoped exception

No single-resource importer yet. Either:

1. **Re-run bulk** (safer): `make bulk-import-dump && make bulk-import-diff DUMP_ID=$(date +%F)` to scope the diff, then `make bulk-import-from-cache` and `git checkout` anything you didn't intend to change.
2. **Hand-author** (faster) using [exceptions/_template.tf.example](terraform/exceptions/_template.tf.example) or [rule_exceptions/_template.tf.example](terraform/rule_exceptions/_template.tf.example).

### 3. Open an adoption MR

```sh
$ git checkout -b drift/adopt-<short-name>
$ git add terraform/ && git commit -m "drift: adopt <name> from Kibana UI"
$ git push origin drift/adopt-<short-name>
```

Prefix the title with `drift:` so adoption MRs are filterable vs. net-new authoring.

### 4. Verify CI plan

- `0/0/0 + N imported` → adoption working.
- `0/0/0 + 1 to change` → tweak the .tf and push again.

The resource exists in Kibana but not yet in state, so an `import {}`
block is required — `import_gui_rule.py` prints the exact command. Drop
it in a temporary `terraform/imports.tf` on the runner; same flow as
Playbook 1 Step 6, but for one resource.

### 5. Merge

After plan is `0/0/0` (with or without imports), merge. State is now
authoritative — future UI edits show up as `1 to change` in nightly drift.

---

# Playbook 3 — Author a net-new rule or exception

> **When:** Detection Engineering wants a rule that doesn't exist yet.
> **Time:** ~15 min for a simple rule. **Risk:** low — fully reviewable in MR.

### 1. Branch + scaffold

```sh
$ git checkout main && git pull && git checkout -b feat/rule-<short-name>
$ make new-rule        # or: make new-exception
```

The wizard ([scripts/new_rule.sh](scripts/new_rule.sh)) writes a
syntactically correct skeleton. You can hand-author too — copy
[custom_rules/_template.tf.example](terraform/custom_rules/_template.tf.example).

### 2. Edit and tune

- KQL/EQL query.
- `Team: <your-team>` tag — required by [tests/test_rules.py](tests/test_rules.py).
- MITRE IDs only — names + URLs auto-resolve via [mitre_lookup.tf](terraform/modules/detection_rule/mitre_lookup.tf).
- **Always start `enabled = false`.** Soak in UI before flipping.

### 3. Local validation

```sh
$ terraform -chdir=terraform fmt -recursive
$ terraform -chdir=terraform init -backend=false
$ terraform -chdir=terraform validate
$ pytest -q
```

### 4. MR

```sh
$ git add terraform/custom_rules/<file>.tf
$ git commit -m "feat: add detection rule for <description>"
$ git push origin feat/rule-<short-name>
```

Plan should show `1 to add, 0 to change, 0 to destroy`.

### 5. Merge & verify

- Phase 2 (`TF_AUTO_APPLY="false"`): merge does **not** deploy; a human runs `terraform apply` on the runner.
- Phase 3+ (`true`): merge exposes a manual-approval apply button on the `main` pipeline.

After apply, the rule is in Kibana → Security → Rules — **disabled**.
Preview against recent data, then enable.

> Toggling `enabled = true` in the UI causes the next nightly plan to
> show `1 to change`. That's a feature, not a bug — it's your reminder
> to formalize the change in code with a one-line MR. Cleaner long-term:
> set `enabled = true` in your next code MR after the soak.

---

## Quick reference

| Task | Command |
|---|---|
| List all rules in the live space | `make list-rules` |
| Dump live Kibana → cache | `make bulk-import-dump` |
| Preview importer drift (no writes) | `make bulk-import-diff DUMP_ID=YYYY-MM-DD` |
| Render TF from cached dump | `make bulk-import-from-cache DUMP_ID=YYYY-MM-DD` |
| New rule / exception skeleton | `make new-rule` · `make new-exception` |
| Import a single GUI rule | `python3 scripts/import_gui_rule.py --name "..."` |
| Local validation | `terraform -chdir=terraform fmt -check -recursive && terraform -chdir=terraform validate && pytest -q` |
| Force CI re-plan | `git commit --allow-empty -m "re-plan" && git push` |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `bulk-import-dump` returns 0 rules | API key scope / wrong space | Regenerate key with `kibana: [{spaces: ["dac"], feature: {siem: ["all"]}}]` |
| Plan wants to "destroy" unexpectedly | Wrong `TF_STATE_KEY` (different env) | Verify CI variable; never share state across envs |
| `1 to change` immediately post-import | Renderer dropped a field | Plan names it — fix [scripts/importers/rules.py](scripts/importers/rules.py), re-render, re-plan |
| `pytest` fails on missing `Team:` tag | No team-prefixed tag | Add `"Team: <name>"` to `tags` |
| `terraform import` says "resource not found" | Used `rule_id` instead of internal Kibana `id` | Different UUIDs — see the comment block in the imported .tf |
| Apply hangs forever | Bad `space_id` / auth | Ctrl+C; re-test creds via `curl` |

---

_Last updated: 2026-05-06._

- **2026-05-06** — Importer round-trips ~17 additional rule fields
  (note/setup/refs/false_positives/max_signals/timeline_*/timestamp/author/
  license/version/alert_suppression + threat_match), regenerates all three
  outputs.tf, auto-runs `terraform fmt`, surfaces `list`-operator entries
  as TODO comments, and ships `--diff-only` preview mode. Renderer guarded
  by [tests/test_importers.py](tests/test_importers.py).
