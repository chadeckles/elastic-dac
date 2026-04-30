# Detection-as-Code — Walkthrough Guide

> **Purpose.** A practitioner-oriented how-to for the detection engineering
> team. Each section is a self-contained task you'll perform during normal
> day-to-day work: authoring a rule, tuning false positives, importing a
> Kibana-built rule, dealing with prebuilt rules, etc.
>
> **Audience.** Detection engineers, SOC analysts who tune rules, and
> platform engineers maintaining the framework.
>
> **Prerequisites.**
>
> - Local Elastic Stack running (`make setup`) **or** access to a remote
>   cluster with the credentials wired into [.env](.env) /
>   [terraform/terraform.tfvars](terraform/terraform.tfvars).
> - Terraform initialized at least once (`make init`).
> - Familiarity with Git branching and merge requests.

---

## Table of contents

1. [Repo orientation](#1-repo-orientation)
2. [Authoring a new custom rule](#2-authoring-a-new-custom-rule)
3. [Adding rule-scoped exceptions (the production-default pattern)](#3-adding-rule-scoped-exceptions-the-production-default-pattern)
4. [Adding a shared exception list (multi-rule scope)](#4-adding-a-shared-exception-list-multi-rule-scope)
5. [Importing a Kibana-built rule into Terraform](#5-importing-a-kibana-built-rule-into-terraform)
6. [Editing an existing rule's query](#6-editing-an-existing-rules-query)
7. [Working with prebuilt rules](#7-working-with-prebuilt-rules)
8. [Forking a prebuilt rule](#8-forking-a-prebuilt-rule)
9. [Building-block rules](#9-building-block-rules)
10. [The full GitLab MR → Apply lifecycle](#10-the-full-gitlab-mr--apply-lifecycle)
11. [Upstream rule sync](#11-upstream-rule-sync)
12. [Local environment lifecycle](#12-local-environment-lifecycle)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Repo orientation

```
elastic-dac/
├── .gitlab-ci.yml                       # Pipeline (test → plan → apply)
├── .gitlab/
│   ├── GITLAB_RUNNERS.md                # AWS S3 + dedicated runner setup
│   └── ci/sync-upstream.gitlab-ci.yml   # Scheduled upstream-sync pipeline
├── terraform/
│   ├── main.tf                          # Provider + backend + child modules
│   ├── backend.tf.example               # Copy → backend.tf to enable S3 state
│   ├── prebuilt_rules.tf                # Elastic prebuilt rule installer
│   ├── modules/
│   │   ├── detection_rule/              # One rule, with optional inline exceptions
│   │   ├── exception_list/              # Shared exception list + items
│   │   └── rule_exception_items/        # Items attached to an existing list
│   ├── custom_rules/                    # One .tf per detection rule
│   ├── exceptions/                      # One .tf per shared exception list
│   └── rule_exceptions/                 # One .tf per rule-scoped tuning bundle
├── scripts/                             # Wizards, importer, sync, validate
├── tests/                               # pytest validation suite
├── docker-compose.yml                   # Optional local Elastic stack
└── Makefile                             # Task shortcuts
```

**Two ways to model exceptions** — pick whichever matches your scope:

| Pattern | Where it lives | Resource | When to use |
|---|---|---|---|
| **Rule-scoped (default)** | inline `rule_exceptions = [...]` on the rule, or a file in [terraform/rule_exceptions/](terraform/rule_exceptions/) | `kibana_security_exception_item` attached to a rule-default list | Tuning **one** rule, analyst-driven false-positive reduction. This is what the Kibana Rules UI writes when you click "Add rule exception". |
| **Shared list (multi-rule)** | a file in [terraform/exceptions/](terraform/exceptions/) | `kibana_security_exception_list` + child items | One container that **multiple** rules reference (e.g. "Trusted Internal Infrastructure"). |

Most exceptions in production end up rule-scoped. Reach for the shared list
only when you know more than one rule will reference it.

---

## 2. Authoring a new custom rule

### Option A — interactive wizard

```bash
make new-rule
```

The wizard prompts for every required field, slugifies the filename, drops the
new module into [terraform/custom_rules/](terraform/custom_rules/), and registers it in
[terraform/custom_rules/outputs.tf](terraform/custom_rules/outputs.tf). No HCL knowledge required.

### Option B — copy the template

```bash
cp terraform/custom_rules/_template.tf.example \
   terraform/custom_rules/006_<short_name>.tf
```

Edit the new file: rename the module, fill in `name`, `description`, `type`,
`severity`, `risk_score`, `tags` (must include a `Team:` tag), `mitre_attack`,
and the rule's `query` / `index` / scheduling. See
[terraform/modules/detection_rule/variables.tf](terraform/modules/detection_rule/variables.tf) for the full interface.

Then register the output:

```hcl
# terraform/custom_rules/outputs.tf
my_new_rule = module.my_new_rule.rule_id
# (and the rule_default_exception_list_id entry, even if null)
```

### Validate, plan, apply

```bash
make test                     # pytest structural validation
cd terraform && terraform init   # required when adding a new module block
make plan                     # preview the diff
make apply                    # deploy locally (CI does this on merge)
```

> ⚠️ Adding a new `module` block in `custom_rules/` (or `exceptions/`,
> `rule_exceptions/`) requires `terraform init` from inside the
> `terraform/` directory. Without it `plan` fails with `Module not installed`.

---

## 3. Adding rule-scoped exceptions (the production-default pattern)

This is the day-to-day analyst loop: an alert fires on a known-good behaviour,
you suppress it with a narrow exception scoped to that one rule.

The `detection_rule` module accepts an inline `rule_exceptions = [...]` list.
When non-empty, the module creates a per-rule exception list (named
`<rule-slug>-exceptions`) and an `elasticstack_kibana_security_exception_item`
for each entry, then attaches the list to the rule automatically.

### 3a. Inline on the rule

Edit the rule's `.tf` file and add:

```hcl
module "brute_force_login" {
  source = "../modules/detection_rule"
  # … existing fields …

  rule_exceptions = [
    {
      item_id     = "brute-force-vuln-scanner"
      name        = "Authorized vulnerability scanner"
      description = "Quarterly scanner deliberately probes auth endpoints."
      tags        = ["vuln-scan", "false-positive-reduction"]
      entries = [{
        field    = "user.name"
        type     = "match"
        operator = "included"
        value    = "svc_vuln_scanner"
      }]
    },
  ]
}
```

`make plan` will show:

- 1 `elasticstack_kibana_security_exception_list.rule_default[0]` to add
- 1 `elasticstack_kibana_security_exception_item.rule_default[\"brute-force-vuln-scanner\"]` to add
- 1 in-place change on the rule itself (its `exceptions_list` now references the new list)

### 3b. In a separate file (analyst tuning)

When more than one analyst tunes the same rule, keep the rule definition
"clean" and add tuning items in [terraform/rule_exceptions/](terraform/rule_exceptions/) instead.

```bash
cp terraform/rule_exceptions/_template.tf.example \
   terraform/rule_exceptions/002_<rule>_extras.tf
```

The template attaches to a sibling rule's auto-created list via:

```hcl
list_id = var.rule_default_lists["brute_force_login"]
```

That map is wired through the root module from
[terraform/custom_rules/outputs.tf](terraform/custom_rules/outputs.tf#L19) — every rule that declares
inline `rule_exceptions` has its `rule_default_exception_list_id` exposed
under its module name. After editing, run `terraform init && make plan`.

### 3c. Why this matches what Kibana writes

When you click **Add rule exception** in the Kibana UI, Kibana auto-creates
a "rule-default" exception list and writes one `exception_item` per
suppression. The pattern above mirrors it exactly — same resource type, same
list shape — so an exception authored in code looks indistinguishable from
one authored in the GUI.

---

## 4. Adding a shared exception list (multi-rule scope)

Use this only when several rules will reference the same list (e.g. a global
"Trusted Infrastructure" allowlist).

```bash
cp terraform/exceptions/_template.tf.example \
   terraform/exceptions/005_<list_name>.tf
```

Fill in `list_id`, `name`, `description`, and `items[]`. Register the output
in [terraform/exceptions/outputs.tf](terraform/exceptions/outputs.tf), then attach the list to whichever
rules need it via their `exceptions_list` variable:

```hcl
exceptions_list = [{
  id             = module.trusted_infrastructure.id
  list_id        = module.trusted_infrastructure.list_id
  namespace_type = "single"
  type           = "detection"
}]
```

> ⚠️ Wiring a shared list from a sibling child module (`exceptions` →
> `custom_rules`) requires either (a) declaring the list at the root and
> passing references in, or (b) using a stable `list_id` literal on both
> sides. The template uses approach (b) for simplicity.

`terraform init && make test && make plan && make apply`.

---

## 5. Importing a Kibana-built rule into Terraform

Detection engineers often prototype in the Kibana UI. Once the rule is
production-worthy, bring it under version control.

```bash
make list-rules                 # show every rule in the cluster
make import-rule NAME="Password Change"
```

The script writes a new `terraform/custom_rules/NNN_<slug>.tf` and prints both
of Kibana's IDs in the file header:

| ID | Used for |
|---|---|
| `rule_id` | Kibana API lookups; lives inside the .tf as `rule_id` |
| `id` (Kibana internal) | The argument to `terraform import` |

Follow the printed steps:

1. **Review** the generated file. Tune tags, `false_positives`, `note`.
2. **Register** in [terraform/custom_rules/outputs.tf](terraform/custom_rules/outputs.tf).
3. `cd terraform && terraform init` to register the new module block.
4. `terraform import 'module.custom_rules.module.<name>.elasticstack_kibana_security_detection_rule.this' 'default/<kibana_id>'`
5. `make plan` — expect `0 to add, ≤1 to change, 0 to destroy`. The change is
   the framework folding in standard tags (`detection-as-code`,
   `terraform-managed`).
6. `make apply`.

> Use the **internal Kibana `id`**, not the `rule_id`, with `terraform import`.
> Both are printed at the top of the generated .tf file.

---

## 6. Editing an existing rule's query

Editing a query is exactly what version control is meant to do. Open the
rule's file, change the `query` value, then:

```bash
make plan
```

The diff is surgical:

```
~ module.custom_rules.module.suspicious_powershell_encoded
    ~ query = "…" → "…"
```

Push, open an MR, get peer review, merge — the apply job pushes the change
to Kibana automatically.

---

## 7. Working with prebuilt rules

Elastic ships ~1,400 prebuilt rules. We **install and update** them via
Terraform; we **enable** them via the Kibana Rules UI.

```bash
cat terraform/prebuilt_rules.tf
```

Toggle `var.install_prebuilt_rules` to `false` to skip them entirely.
Otherwise, `terraform apply` installs the latest prebuilt rules into your
cluster. Pick which ones to enable in **Security → Rules → bulk actions**.

We deliberately do **not** model 1,400 rules in `.tf` files. Kibana already
has bulk-action and tag-based filtering UIs purpose-built for this; replicating
them in Terraform would be friction without value.

---

## 8. Forking a prebuilt rule

Kibana 8.17+ treats prebuilt rules as immutable. To customise one beyond
what exceptions allow, **duplicate → edit → import**:

1. In Kibana, open the prebuilt rule → **⋯ → Duplicate rule**.
2. Edit the duplicate (rename it, narrow the query, change severity, etc.).
3. `make import-rule NAME="<duplicate name>"` and follow §5.
4. (Optional) Disable the original prebuilt rule to avoid duplicate alerts.

The fork is now a regular custom rule under your control. Elastic's updates
to the original keep flowing in; you get to decide if/when to merge them.

---

## 9. Building-block rules

Building-block rules feed correlation rules instead of generating direct
alerts. To convert a rule, add one attribute:

```hcl
building_block_type = "default"
```

`make plan` shows a single in-place change. `make apply`. Reverting is
identical — remove the line, plan, apply.

---

## 10. The full GitLab MR → Apply lifecycle

```
git checkout -b feat/<short-description>
# … edit terraform/ files …
make test            # local validation
make plan            # local preview
git add terraform/
git commit -m "feat: <what changed>"
git push -u origin HEAD
```

Open a Merge Request to `main`. The pipeline ([.gitlab-ci.yml](.gitlab-ci.yml)) runs:

1. **`pytest`** — structural validation of every rule and exception.
2. **`terraform:fmt`** — formatting check.
3. **`terraform:validate`** — HCL + provider schema.
4. **`terraform:plan`** — produces a `tfplan` artifact and a human-readable
   diff in `tfplan.txt`.
5. **`terraform:plan-summary`** — surfaces the plan inline on the MR.

Reviewers approve. Merge to `main`. The pipeline re-runs through to:

6. **`terraform:apply`** — manual approval, then `terraform apply tfplan`
   against production. `resource_group: production-apply` serialises any
   concurrent applies.

State lives in S3 with DynamoDB locking. See
[.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md) for the AWS provisioning, IAM policy,
and runner registration walkthrough.

> **Rollback.** Revert the offending commit, open an MR, merge. Apply runs
> against the reverted state. No SSH, no Kibana clicks.

---

## 11. Upstream rule sync

A scheduled GitLab pipeline ([`.gitlab/ci/sync-upstream.gitlab-ci.yml`](.gitlab/ci/sync-upstream.gitlab-ci.yml))
diffs the upstream [`elastic/detection-rules`](https://github.com/elastic/detection-rules)
repo against the last synced SHA, regenerates `UPSTREAM_CHANGELOG.md`, and
opens an MR.

To configure: **Settings → CI/CD → Schedules → New schedule** with
`SYNC_UPSTREAM=true` and a cron of `0 8 * * 1` (Mondays 08:00 UTC). Details:
see [.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md#5-schedule-the-upstream-sync-pipeline).

To run locally without the pipeline:

```bash
make sync-upstream-dry        # changelog only, no tracking update
make sync-upstream            # full sync
make sync-upstream-full       # first-time baseline catalog
```

---

## 12. Local environment lifecycle

```bash
make setup           # docker compose up + passwords + terraform init
make validate-lab    # health check ES + Kibana + rules
make plan / apply
make teardown        # destroy terraform resources + bring docker down
```

A faster reset between practice runs (reverts uncommitted changes, redeploys
baseline) is `make demo-reset`.

---

## 13. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Error: Module not installed` | New `module` block added without re-init | `cd terraform && terraform init` |
| `409 Conflict` on apply after import | `terraform import` used `rule_id` instead of internal Kibana `id` | Re-import using the `id` printed in the .tf header |
| Plan shows drift on tags after import | Framework folding in standard tags | Expected; apply once to converge |
| `Could not lock state` | Another pipeline holds the S3 native lock (`<key>.tflock` object) | Wait for the conflicting `terraform:apply` job to finish, or release manually: `aws s3 rm s3://$TF_STATE_BUCKET/$TF_STATE_KEY.tflock` |
| `RequestError: 403` on `terraform plan` in CI | Runner instance role missing S3 perms or pipeline lacks the protected variables | Verify the runner IAM role includes the policy in [.gitlab/GITLAB_RUNNERS.md §1c](.gitlab/GITLAB_RUNNERS.md#1c-iam-policy-for-the-runner) and the MR is on a protected branch |
| Local apply uses local state but CI uses S3 | Backend partial-config not provided locally | Use `terraform init -reconfigure -backend-config=local.s3.tfbackend`, or develop without `backend.tf` and only enable it in CI |
| Rule not visible in Kibana after apply | Wrong space, or `var.kibana_space_id` mismatch | Confirm `kibana_space_id` matches the space you're viewing |

---

## Quick command reference

| Task | Command |
|---|---|
| Bootstrap local stack | `make setup` |
| Health check | `make validate-lab` |
| Create a rule (wizard) | `make new-rule` |
| Create a shared exception list (wizard) | `make new-exception` |
| List rules in Kibana | `make list-rules` |
| Import a GUI rule | `make import-rule NAME="<rule name>"` |
| Run unit tests | `make test` |
| Preview changes | `make plan` |
| Deploy locally | `make apply` |
| Tear down | `make teardown` |
| Print cheatsheet | `make cheatsheet` |
