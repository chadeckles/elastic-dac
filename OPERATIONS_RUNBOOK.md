# Operations Runbook — Detection as Code

> **Purpose:** Step-by-step playbooks for the day-to-day operations of this
> repo, written for use **in an isolated lab environment** where you can't
> ask questions in real time. Each step has a short "why" so you understand
> what's happening, not just what to type.
>
> **Companion docs:**
> - [README.md](README.md) — architecture, modules, CI overview
> - [IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md) — the phased migration plan
> - [.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md) — runner & AWS setup
>
> **Three playbooks below:**
> 1. [First-time brownfield import](#playbook-1--first-time-brownfield-import) — pull current Kibana config into Terraform
> 2. [Adopt a UI-created rule or exception](#playbook-2--adopt-a-ui-created-rule-or-exception) — analyst made it in Kibana, get it into the repo
> 3. [Author a net-new rule or exception in code](#playbook-3--author-a-net-new-rule-or-exception-in-code) — write it in TF, deploy via CI

---

## Conventions used below

- `$` prefix means run on your **laptop / workstation**.
- `runner$` prefix means run on the **GitLab runner host** (SSH).
- `kibana$` means click in the **Kibana UI**.
- All paths are relative to the repo root unless noted.
- Code blocks you can copy/paste verbatim; placeholders are `<like-this>`.

---

## Pre-flight — every session

Before any of the playbooks, do this once per session in your shell:

```sh
$ cd /path/to/elastic-dac

# These two are needed for any script that talks to Kibana.
$ export KIBANA_ENDPOINT=https://<your-kb-host>:9243
$ export KIBANA_API_KEY=<encoded-api-key>

# Sanity check — does the API key work?
$ curl -sf -H "Authorization: ApiKey $KIBANA_API_KEY" \
    "$KIBANA_ENDPOINT/api/detection_engine/rules/_find?per_page=1" \
    | head -c 400 && echo
```

**Why:** if this `curl` fails, **stop**. None of the scripts will work, and
you'll waste an hour chasing the wrong problem. Common failures:
- 401 → key is wrong, expired, or scoped to the wrong space.
- TLS error → cert trust issue on your laptop.
- Connection refused → wrong port (most clusters are `:9243`, not `:443`).

---

# Playbook 1 — First-time brownfield import

> **When to use this:** exactly **once**, the first time you bring an
> existing Kibana space under Terraform management. After this, the repo's
> state knows about every existing rule and exception, and `terraform plan`
> becomes meaningful (it shows real diffs against live config, not "create
> everything").
>
> **Time required:** 1–3 hours, mostly waiting on plan output.
> **Risk level:** Low if you follow the plan-must-be-empty rule. The bulk
> import is read-only on Kibana — Terraform only writes to *its own state*,
> not to Kibana. The first time Kibana is mutated is at the very end, and
> only if you explicitly approve.
>
> **You will need:**
> - The 6 GitLab CI variables already set (see [README §CI/CD Pipeline](README.md#cicd-pipeline)).
> - SSH access to the runner host (or Pattern B below if not).
> - Kibana API key with read on detection rules + exception lists.

## Step 1 — Snapshot Kibana for rollback (Phase 0)

```sh
kibana$ Stack Management → Saved Objects → Export
       → Filter to: rule, exception-list, exception-list-agnostic
       → Save the .ndjson somewhere safe (S3, shared drive)
```

**Why:** if anything goes catastrophically wrong, you can re-import this
file via the same UI and you're back where you started. This snapshot is
cheap insurance — take it every time, even if you're sure.

## Step 2 — Dump live Kibana to a local cache

```sh
$ make bulk-import-dump
```

**What it does:** pages through `/api/detection_engine/rules/_find`,
`/api/exception_lists/_find` + items, and the rule-default lists, writing
raw JSON under `.import-cache/<today>/`.

**Why a cache:** so you can re-render `.tf` files as many times as you want
without hammering the Kibana API. The cache is gitignored — it stays local.

```sh
# Verify volume — sanity check before continuing.
$ DUMP=$(date +%F)
$ ls .import-cache/$DUMP/
$ wc -l .import-cache/$DUMP/rules/*.json \
        .import-cache/$DUMP/exception_lists/*.json \
        .import-cache/$DUMP/rule_exceptions/*.json
```

**Red flags:** zero rules dumped (API key scope), or 10× more rules than
you expected (you accidentally dumped a different space). Stop and verify
before rendering.

## Step 3 — Render Terraform files from the cache

```sh
$ make bulk-import-from-cache DUMP_ID=$(date +%F)
```

**What it does:** reads the cached JSON and writes:
- `.tf` files into [terraform/custom_rules/](terraform/custom_rules/), [terraform/exceptions/](terraform/exceptions/), [terraform/rule_exceptions/](terraform/rule_exceptions/) — these are committed to git.
- `terraform/imports.tf` — Terraform 1.5+ `import {}` blocks. **Gitignored** by design (one-shot use).
- `scripts/import.generated.sh` — equivalent CLI commands as a fallback. Also gitignored.

**Why two output formats:** `import {}` blocks are the modern way (single
`terraform apply` does the import). The shell script is a fallback if you
ever need to import resources one at a time, e.g. troubleshooting a single
failure.

## Step 4 — Review what was generated

```sh
$ git status                    # should show many new .tf files
$ git diff terraform/ | less    # skim — looking for obvious render bugs
```

**What to spot-check:**
- Every rule has a `Team:` tag. Importer adds `Team: Imported` if missing.
- `threat[]` blocks have non-empty IDs (no `""`-only entries).
- Exception `entries` look right: `field`, `type`, `operator`, `value`/`values`.
- Index lists aren't truncated (some heavy rules pull from 20+ indices).

**Why this matters:** `terraform plan` will compare these files against
live Kibana. If a field rendered wrong, plan will say "modify" instead of
"no change," and you'll need to fix the .tf and re-render.

## Step 5 — Open a feature branch and MR

```sh
$ git checkout -b brownfield/initial-import
$ git add terraform/
$ git status                    # imports.tf is gitignored — that's correct
$ git commit -m "Phase 1: initial import of <space-id> space"
$ git push origin brownfield/initial-import
```

Open the MR in GitLab. CI will run `pytest`, `fmt`, `validate`, `plan`.

> **The plan on this MR will say "create N resources."** That's expected
> — the runner doesn't have `imports.tf` yet (it's gitignored). This MR is
> only for validating that the rendered files compile and pass tests.
>
> **Do not merge this MR yet.**

**Why we still bother with this MR:** if `fmt`/`validate`/`pytest` fail
here, the bulk render produced something invalid. Cheaper to find out now
than after the import.

## Step 6 — Run the import on the runner

This is the only step that mutates state. Two patterns; pick one.

### Pattern A — SSH to the runner (recommended for first run)

```sh
# From your laptop, copy the gitignored files onto the runner:
$ scp terraform/imports.tf <runner>:/tmp/
$ scp scripts/import.generated.sh <runner>:/tmp/

# Then SSH to the runner and pull the same branch the MR is on:
$ ssh <runner>

runner$ git clone <gitlab-repo-url>           # if not already cloned
runner$ cd elastic-dac
runner$ git fetch origin
runner$ git checkout brownfield/initial-import
runner$ cp /tmp/imports.tf terraform/imports.tf

runner$ cd terraform
runner$ export AWS_DEFAULT_REGION=<region>
runner$ export TF_STATE_BUCKET=<bucket>
runner$ export TF_STATE_KEY=<key>
runner$ export KIBANA_ENDPOINT=<url>
runner$ export KIBANA_API_KEY=<encoded>

runner$ terraform init \
          -backend-config="bucket=$TF_STATE_BUCKET" \
          -backend-config="key=$TF_STATE_KEY" \
          -backend-config="region=$AWS_DEFAULT_REGION" \
          -backend-config="use_lockfile=true" \
          -backend-config="encrypt=true"

runner$ terraform plan
```

**Stop and read carefully.** The plan output should look approximately like:

```
Plan: 0 to add, 0 to change, 0 to destroy.

The following resources will be imported:
  module.custom_rules.module.<rule_a>.elasticstack_kibana_security_detection_rule.this
  module.custom_rules.module.<rule_b>.elasticstack_kibana_security_detection_rule.this
  module.exceptions.module.<list_a>.elasticstack_kibana_security_exception_list.this
  ... [many more lines] ...
```

**The numbers must be `0 to add, 0 to change, 0 to destroy`.** If anything
else, **abort**:
- "1 to add" → resource is in code but not in Kibana. Render bug or you're
  pointed at the wrong space.
- "1 to change" → field rendered differently than what's live. Fix the .tf
  and re-render.
- "1 to destroy" → STOP IMMEDIATELY. Something is very wrong. Do not apply.

If plan looks right, apply:

```sh
runner$ terraform apply
# Type 'yes' when prompted, after re-reading the summary.

runner$ rm imports.tf            # CRITICAL — these are one-shot directives
runner$ terraform plan           # MUST now show: "No changes."
```

**Why `rm imports.tf` matters:** an `import {}` block referencing a
resource that's already in state is harmless on subsequent plans, but
leaving the file around is confusing and clutters the runner. Delete it.

### Pattern B — Manual CI job (if no SSH access)

If your platform team won't give shell on the runner, add a temporary
manual-trigger job to [.gitlab-ci.yml](.gitlab-ci.yml) (revert it after
the import). Ask the AI assistant or platform engineer to add a
`terraform:bulk-import` job following the pattern in
[IMPLEMENTATION_STRATEGY.md §Phased Rollout](IMPLEMENTATION_STRATEGY.md#phased-rollout).
Don't try to wing this in the lab — it's the riskiest variation.

## Step 7 — Final validation in CI

Back on your laptop:

```sh
$ git checkout brownfield/initial-import
$ git commit --allow-empty -m "trigger CI re-plan after import"
$ git push
```

The MR's `terraform:plan` job should now show **"No changes."** That's the
green light.

```sh
# Merge the MR via GitLab UI.
```

**Why we trigger an empty commit:** to force CI to re-run plan against the
now-hydrated state. Even though state is in S3 and visible to CI, the
pipeline only runs on push events.

## Step 8 — Stay in plan-only mode (Phase 2)

`TF_AUTO_APPLY` should still be `"false"`. CI will run plan-only on every
MR and (once you set up the schedule) nightly. **Do not flip to `"true"`
yet.** Phase 2 of [IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md)
is where you live for the next 2–3 weeks while the team validates that the
imported config is faithful and the drift loop catches UI activity.

---

# Playbook 2 — Adopt a UI-created rule or exception

> **When to use this:** an analyst created (or modified) a rule or
> exception in the Kibana UI and you want to bring that change into the
> repo. This is the most common Phase 4 / steady-state workflow.
>
> **Time required:** 10–20 minutes per resource.
> **Risk level:** Very low. Same import flow as Playbook 1, just smaller
> scope.

## When you'd notice you need to do this

- **Nightly CI plan is non-empty.** The drift loop flagged it. Open the
  pipeline → grab the resource address from the plan output.
- **Analyst drops you a Microsoft Teams message about a new change** "I made a new rule, can you put it in code?"
- **You were about to author a TF rule** and noticed it already exists in
  the UI.

## Step 1 — Identify the resource

For a single rule, you need either its name or its `rule_id`:

```sh
$ make list-rules                          # browse all rules in the space
# OR
$ python3 scripts/import_gui_rule.py --list | grep -i "<keyword>"
```

For an exception list, find its `list_id` in
*Kibana → Security → Manage → Exception lists*.

## Step 2a — If it's a rule: use the single-rule importer

```sh
$ python3 scripts/import_gui_rule.py --name "My New Rule"
# or by exact ID:
$ python3 scripts/import_gui_rule.py --rule-id <uuid>
```

**What it does:** generates a single `.tf` file under
[terraform/custom_rules/](terraform/custom_rules/) and prints a
`terraform import` command for the runner.

**Why we have two importers:** the bulk one is for the brownfield event;
this one is for steady-state, single resources, and includes a friendlier
prompt + manual instructions.

## Step 2b — If it's an exception list or rule-scoped exception

We don't yet have a single-resource importer for these. Two options:

1. **Re-run the bulk importer with `--only`** — rendering will overwrite
   any matching .tf files in place:
   ```sh
   $ make bulk-import-dump
   $ make bulk-import-from-cache DUMP_ID=$(date +%F)
   ```
   Then `git diff terraform/exceptions/` and `git diff terraform/rule_exceptions/`
   to see only the new/changed lists. Discard everything else with
   `git checkout terraform/<unchanged-files>`.

2. **Hand-author** following the patterns in
   [terraform/exceptions/_template.tf.example](terraform/exceptions/_template.tf.example)
   or [terraform/rule_exceptions/_template.tf.example](terraform/rule_exceptions/_template.tf.example).
   Faster for one or two items.

Option 1 is safer; Option 2 is faster.

## Step 3 — Open an adoption MR

```sh
$ git checkout -b drift/adopt-<short-name>
$ git add terraform/
$ git commit -m "drift: adopt <name> from Kibana UI"
$ git push origin drift/adopt-<short-name>
```

Open the MR. **Title convention:** prefix with `drift:` so the detection
team can filter for adoption MRs vs. net-new authoring.

## Step 4 — Verify CI plan

The MR's `terraform:plan` should show:

- **0 to add, 0 to change, 0 to destroy** + a single resource being
  *imported* into state — perfect, this is adoption working.
- **0 to add, 1 to change** — the .tf doesn't quite match the live
  resource. Tweak the .tf and push again.

**You will need an `import {}` block** because the resource exists in
Kibana but not yet in Terraform state. The `import_gui_rule.py` script
prints the exact command; copy it into a temporary `terraform/imports.tf`
on the runner and apply, same as Playbook 1 Step 6 — but for one resource
instead of all.

## Step 5 — Merge

After plan is `0/0/0` (or `0/0/0 + N to import`), merge. State is now
authoritative for this resource. Future UI edits to it will show up in the
nightly drift plan as `1 to change` — you'll know.

---

# Playbook 3 — Author a net-new rule or exception in code

> **When to use this:** Detection Engineering wants a brand-new rule that
> doesn't yet exist in Kibana. Code-first.
>
> **Time required:** 15 minutes for a simple rule, longer if you're tuning
> the query.
> **Risk level:** Low — the entire flow is reviewable in an MR before
> anything lands in Kibana.

## Step 1 — Pre-flight

```sh
$ cd /path/to/elastic-dac
$ git checkout main && git pull
$ git checkout -b feat/rule-<short-name>
```

## Step 2 — Generate skeleton with the wizard

```sh
$ make new-rule
```

**What it does:** the [scripts/new_rule.sh](scripts/new_rule.sh) wizard
prompts for name, type, severity, query, MITRE IDs, etc., and writes a new
`.tf` file under [terraform/custom_rules/](terraform/custom_rules/).

**Why a wizard:** so detection engineers who don't write Terraform daily
get a syntactically correct skeleton without having to remember module
inputs. You can absolutely hand-author too — copy
[terraform/custom_rules/_template.tf.example](terraform/custom_rules/_template.tf.example).

For an exception:
```sh
$ make new-exception
```

## Step 3 — Edit and refine

Open the generated file and tune:
- The KQL/EQL query.
- Tag with `Team: <your-team>` (required by [tests/test_rules.py](tests/test_rules.py)).
- MITRE IDs only — the module auto-resolves names and reference URLs from
  [terraform/modules/detection_rule/mitre_lookup.tf](terraform/modules/detection_rule/mitre_lookup.tf).
- Set `enabled = false` initially. **Always start disabled.** Let the team
  review the live rule in the UI before flipping it on.

## Step 4 — Local validation

```sh
$ terraform -chdir=terraform fmt -recursive
$ terraform -chdir=terraform init -backend=false
$ terraform -chdir=terraform validate
$ pytest -q
```

**Why each step:**
- `fmt` — CI will fail on unformatted files. Cheaper to fix locally.
- `init -backend=false` — sets up providers without touching S3 state.
- `validate` — catches typos in module inputs.
- `pytest` — catches missing `Team:` tags, malformed MITRE, etc.

## Step 5 — Open an MR

```sh
$ git add terraform/custom_rules/<new-file>.tf
$ git commit -m "feat: add detection rule for <description>"
$ git push origin feat/rule-<short-name>
```

Open the MR. CI runs `pytest`, `fmt`, `validate`, `plan`.

**The plan should show:** `1 to add, 0 to change, 0 to destroy` — i.e.
"create the new rule." That's the desired output for net-new authoring.

## Step 6 — Review and merge

- Code review by another detection engineer (or your team's process).
- If `TF_AUTO_APPLY="false"` (Phase 2), merging does **not** deploy the
  rule. CI runs plan on `main` but apply doesn't appear. The rule lands
  only when a human runs apply manually on the runner.
- If `TF_AUTO_APPLY="true"` (Phase 3+), merging shows a manual-approval
  apply button on the `main` pipeline. Click it when ready.

## Step 7 — Verify in Kibana

After apply, the rule appears in Kibana → Security → Rules → Detection
rules — **disabled** (because you set `enabled = false`).

```sh
kibana$ Find your new rule → Preview → run against a recent index
       → if results look reasonable, enable it.
```

> **Wait — won't enabling it in Kibana cause drift?** No, because
> `enabled` is a managed field. The next nightly plan will show
> `1 to change: enabled false → true`. **That's a flag for you to
> formalize the change in code.** Open a one-line MR setting
> `enabled = true` and merge. Now state agrees with reality.
>
> Alternative: skip the UI toggle entirely — set `enabled = true` in your
> next MR after the rule has soaked. This is the cleaner long-term flow.

---

## Quick reference — common operations

| Task | Command |
|---|---|
| List all rules in the live space | `make list-rules` |
| Dump live Kibana to local cache | `make bulk-import-dump` |
| Render TF from cached dump | `make bulk-import-from-cache DUMP_ID=YYYY-MM-DD` |
| Generate a new rule skeleton | `make new-rule` |
| Generate a new exception skeleton | `make new-exception` |
| Import a single GUI rule | `python3 scripts/import_gui_rule.py --name "..."` |
| Run all local validation | `terraform -chdir=terraform fmt -check -recursive && terraform -chdir=terraform validate && pytest -q` |
| Force CI re-plan with no code change | `git commit --allow-empty -m "re-plan" && git push` |

---

## Troubleshooting cheatsheet

| Symptom | Most likely cause | Fix |
|---|---|---|
| `make bulk-import-dump` returns 0 rules | API key lacks read on detection rules, or wrong space | Regenerate API key with `kibana: [{spaces: ["dac"], feature: {siem: ["all"]}}]` role |
| Plan shows resources to "destroy" you didn't expect | Wrong `TF_STATE_KEY` (pointed at a different env's state) | Verify CI variable; never share state keys between environments |
| Plan shows "1 to change" right after import | Generator rendered something differently than Kibana | `terraform plan` output names the field — fix the .tf, re-render, re-plan |
| `pytest` fails with `Team:` tag missing | Rule doesn't have a Team-prefixed tag | Add `"Team: <name>"` to `tags`; the importer auto-stamps `Team: Imported` for migrated rules |
| Plan-summary job posts nothing on MR | The plan was empty; nothing to summarize | Expected — empty plan = no diff to render |
| `terraform import` fails: "resource not found" | Used the `rule_id` instead of the internal Kibana `id` | They're different UUIDs. Check the comment block in the imported .tf — it lists both. |
| Apply hangs forever | Missing or wrong `space_id`; provider waiting on auth | `Ctrl+C`, verify `KIBANA_ENDPOINT` + `KIBANA_API_KEY` work via `curl` |

---

_Last updated: 2026-05-01. Update this date and append a note when you
discover something the runbook didn't cover. Future-you will thank you._
