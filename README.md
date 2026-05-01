# Detection as Code — Elastic Security + Terraform

> **A production-ready framework for managing Elastic Security detection rules,
> exceptions, and prebuilt rules using Terraform — following Elastic's
> [Detections as Code (DaC)](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features) methodology.**

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Workflow](#workflow)
- [Terraform Modules](#terraform-modules)
- [Adding a New Rule](#adding-a-new-rule)
- [Adding an Exception](#adding-an-exception)
- [Importing a GUI-Created Rule](#importing-a-gui-created-rule)
- [Brownfield Migration (Bulk Import)](#brownfield-migration-bulk-import)
- [Unit Testing](#unit-testing)
- [CI/CD Pipeline](#cicd-pipeline)
- [Upstream Rule Sync](#upstream-rule-sync)
- [Make Targets](#make-targets)
- [References](#references)

---

## Overview

This project implements **Detection as Code (DaC)** for Elastic Security using
the [`elastic/elasticstack`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs)
Terraform provider. DaC applies software engineering practices — version control,
peer review, automated testing, and CI/CD pipelines — to security detection rule
management.

### What's Included

| Component | Purpose |
|---|---|
| **Terraform Modules** | Reusable modules for detection rules & exception lists |
| **Custom Rule Definitions** | Example rules (KQL, EQL, threshold) with MITRE ATT&CK mapping |
| **Exception Lists** | Exception containers with sample items for false-positive reduction |
| **Prebuilt Rules** | Optional install of Elastic's vendor-provided rules |
| **Pytest Suite** | Unit tests enforcing Team tags, MITRE mapping, field validation |
| **GitLab CI/CD** | MR pipelines run `terraform plan`, manual-approval `apply` on `main`, S3-backed state, dedicated self-hosted runners |
| **Interactive Wizards** | `make new-rule` and `make new-exception` for non-coder detection engineers |
| **GUI Rule Import** | `make import-rule` brings Kibana-created rules into Git/Terraform |
| **Bulk Brownfield Import** | `make bulk-import` Terraformizes an existing heavy Kibana config in one pass — see [IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md) |
| **Operations Runbook** | Step-by-step lab playbooks for import, drift adoption, and net-new authoring — see [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) |
| **MITRE ATT&CK Lookup** | ID-only MITRE mapping — module auto-resolves names and URLs |
| **Upstream Sync** | Weekly automated sync from Elastic's detection-rules repo |

### Key DaC Principles

Per [Elastic's DaC guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features):

- **Version control** — All rules live in Git; every change is tracked
- **Peer review** — Merge requests gate all rule changes; the plan output is
  surfaced as an MR comment by the GitLab pipeline
- **Automated testing** — Pytest validates rule structure, tags, MITRE mapping
- **Automated deployment** — `terraform apply` on merge to `main`
- **Consistency** — Modules enforce standards across all rules
- **Team routing** — `Team: <name>` tags on every rule for triage routing

### What Terraform Manages (and What It Doesn't)

A common concern is that adopting DaC means managing **everything** in Terraform.
That's not the case. This framework deliberately splits responsibilities between
Terraform and Kibana based on what each tool does best:

| Responsibility | Managed in | Why |
|---|---|---|
| **Custom detection rules** | Terraform (`custom_rules/`) | Your org writes these — they need version control, peer review, and CI/CD |
| **Rule-scoped exception items** | Terraform (`rule_exceptions/` or inline on the rule) | Mirror what the Kibana Rules UI writes when you click "Add rule exception" — narrow, per-rule suppression |
| **Shared exception lists** | Terraform (`exceptions/`) | Multi-rule suppression containers reviewed and tracked in Git |
| **Prebuilt rule installation & updates** | Terraform (`prebuilt_rules.tf`) | Keeps vendor rules current automatically across environments |
| **Prebuilt rule enablement** | Kibana Rules UI | Kibana has purpose-built filtering, bulk actions, and tag-based selection for this — no need to replicate it in code |
| **Alert triage & investigation** | Kibana Security app | Operational work that doesn't belong in code |
| **Dashboard & visualization** | Kibana | UI-native, not infrastructure |

**The bottom line:** Terraform owns the things that benefit from code review and
version history (custom rules, exceptions, prebuilt rule updates). Kibana owns
the operational decisions (which prebuilt rules to enable, alert triage,
dashboards). Detection engineers do **not** need to manage 1,400+ prebuilt rules
in `.tf` files.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Git Repository                           │
│  terraform/custom_rules/  →  One .tf per Detection Rule         │
│  terraform/exceptions/    →  One .tf per Exception List         │
│  terraform/modules/       →  Reusable TF Modules                │
│  tests/                   →  Pytest Unit Tests                  │
└──────────────┬──────────────────────────────────┬───────────────┘
               │ MR → plan                       │ merge → apply
               ▼                                  ▼
┌────────────────────┐            ┌────────────────────────┐
│   GitLab CI — Plan   │            │   GitLab CI — Apply      │
│  ┌────────────────┐  │            │  ┌─────────────────────┐ │
│  │ terraform fmt   │  │            │  │ terraform apply     │ │
│  │ terraform init  │  │            │  │  → Detection Rules  │ │
│  │ terraform plan  │  │            │  │  → Exception Lists  │ │
│  │ pytest tests    │  │            │  │  → Prebuilt Rules   │ │
│  └────────────────┘  │            │  └─────────────────────┘ │
└──────────────────────┘            └─────────────┬────────────┘
                                                  │
                                                  ▼
                                    ┌──────────────────────────┐
                                    │     Elastic Security     │
                                    │  ┌────────────────────┐  │
                                    │  │ Elasticsearch       │  │
                                    │  │ Kibana              │  │
                                    │  │ Detection Engine    │  │
                                    │  └────────────────────┘  │
                                    └──────────────────────────┘
```

---

## Project Structure

```
elastic-dac/
├── .gitlab-ci.yml               # GitLab CI/CD pipeline
├── .gitlab/
│   ├── GITLAB_RUNNERS.md        # AWS S3 + dedicated runner setup guide
│   └── ci/sync-upstream.gitlab-ci.yml   # Scheduled upstream-sync pipeline
├── terraform/
│   ├── main.tf                  # Provider config + child module calls
│   ├── backend.tf.example       # Copy → backend.tf to enable S3 remote state
│   ├── variables.tf             # Root variables
│   ├── outputs.tf               # Root outputs
│   ├── prebuilt_rules.tf        # Elastic prebuilt rule management
│   ├── modules/
│   │   ├── detection_rule/      # One detection rule + optional inline exceptions
│   │   │   └── mitre_lookup.tf  # MITRE ATT&CK ID → name/URL lookup maps
│   │   ├── exception_list/      # Shared exception list + items
│   │   └── rule_exception_items/   # Items attached to an existing list
│   ├── custom_rules/            # One numbered .tf file per detection rule
│   ├── exceptions/              # One .tf file per shared exception list
│   └── rule_exceptions/         # One .tf file per rule-scoped tuning bundle
├── tests/                       # Pytest unit tests
├── scripts/                     # Wizards, importer, sync helpers
│   ├── import_gui_rule.py       # Import a Kibana GUI rule into Terraform
│   ├── new_rule.sh              # Interactive wizard — new detection rule
│   ├── new_exception.sh         # Interactive wizard — new exception list
│   ├── sync_upstream_rules.py   # Diff against elastic/detection-rules
│   └── dac-sync.sh              # detection-rules CLI integration (optional)
├── Makefile                     # Shortcut targets
├── WALKTHROUGH.md               # Practitioner how-to guide
└── README.md
```

**Convention:** Rule and exception files use a numbered prefix (`001_`, `002_`, …)
for visual ordering. Copy `_template.tf.example` in the respective directory to
add a new one, or use the interactive wizards (`make new-rule` / `make new-exception`).

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| [Terraform](https://developer.hashicorp.com/terraform/downloads) | ≥ 1.10 | Infrastructure as Code engine (1.10 enables S3 native state locking) |
| [Python](https://www.python.org/) | ≥ 3.9 | Run unit tests + helper scripts |
| [Make](https://www.gnu.org/software/make/) | any | Task runner (optional) |

You also need:

- **Live Elasticsearch + Kibana** (Elastic Cloud, on-prem, or self-managed) reachable from your machine and from the GitLab runner.
- **An API key** generated in Kibana → **Stack Management → API Keys**. Use the `encoded` value the API/UI returns. The key needs Kibana **Security: All** privileges (or equivalent role descriptors) to manage detection rules and exception items.
- For CI deploys: a GitLab project with the dedicated runner + AWS S3 backend wired up per [.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md).

---

## Getting Started

### 1. Clone

```bash
git clone <your-repo-url> elastic-dac
cd elastic-dac
```

### 2. Point Terraform at your live cluster

Export the two env vars the elasticstack provider reads automatically:

```bash
export KIBANA_ENDPOINT="https://<deployment>.kb.<region>.aws.elastic-cloud.com:9243"
export KIBANA_API_KEY="<encoded API key>"
```

> **Where do I find these?** `KIBANA_ENDPOINT` is the URL in your browser's
> address bar when logged into Kibana (drop everything after the port).
> `KIBANA_API_KEY` is the `encoded` field returned when you create an API
> key in **Stack Management → API keys**.

Verify connectivity before doing anything else:

```bash
make creds-check
# → ✓ Kibana 8.17.4 available
# → ✓ Elasticsearch authenticated as <user> roles=[...]
```

### 3. Initialise Terraform

Once the [S3 backend](terraform/backend.tf.example) is enabled, init pulls the
remote state down. Pass the same `-backend-config` flags the pipeline uses
(see [.gitlab-ci.yml](.gitlab-ci.yml) `.terraform-init` snippet) or store them in a local
backend file.

```bash
cd terraform
cp backend.tf.example backend.tf       # one-time
terraform init \
  -backend-config="bucket=$TF_STATE_BUCKET" \
  -backend-config="key=$TF_STATE_KEY" \
  -backend-config="region=$AWS_DEFAULT_REGION" \
  -backend-config="use_lockfile=true" \
  -backend-config="encrypt=true"
cd ..
```

### 4. Run unit tests

```bash
make test
```

### 5. Preview and deploy

```bash
make plan        # Review what will change
make apply       # Deploy rules + exceptions to Elastic
```

### 6. Verify in Kibana

Open your Kibana → **Security → Rules** to see deployed detection rules and
**Security → Rules → Shared Exception Lists** for shared exceptions.

---

## Workflow

### Local Development

```
Copy _template.tf.example → terraform/custom_rules/NNN_my_rule.tf
  (or run: make new-rule)
         │
         ▼
    make test          ← Pytest validates rule structure
         │
         ▼
    make plan          ← Preview Terraform changes
         │
         ▼
    make apply         ← Deploy to Elastic Security
```

### CI/CD (Merge Request → Apply)

```
Push branch → Open MR
         │
    ┌────┴───────────────────┐
    │ pytest tests           │
    │ terraform fmt -check   │
    │ terraform validate     │
    │ terraform plan         │
    └────┬───────────────────┘
         │
    Plan summary surfaced inline on the MR
         │
    MR approved → merged to main
         │
    `TF_AUTO_APPLY="true"` (CI var) → manual-approval button appears
         │
    Manual approval on `terraform:apply` job
         │
         ▼
    terraform apply tfplan  (S3 state, DynamoDB lock)
         │
    Rules deployed to Elastic Security
```

---

## Terraform Modules

### `detection_rule`

Wraps [`elasticstack_kibana_security_detection_rule`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_detection_rule).
Creates **one** detection rule per module call from individual `.tf` files in
`custom_rules/`.

<details>
<summary>Module interface</summary>

| Input | Type | Description |
|---|---|---|
| `name` | `string` | Rule display name |
| `description` | `string` | Rule description |
| `type` | `string` | Rule type (query, eql, esql, threshold, new_terms, threat_match, machine_learning) |
| `query` | `string` | Detection query (KQL or EQL) |
| `language` | `string` | Query language (kuery, lucene, eql, esql) |
| `severity` | `string` | low / medium / high / critical |
| `risk_score` | `number` | 0–100 |
| `tags` | `list(string)` | Must include a `Team:` tag |
| `threat` | `list(object)` | MITRE ATT&CK mapping (verbose format) |
| `mitre_attack` | `list(object)` | **Simplified** MITRE mapping — just IDs, module resolves names/URLs |
| `enabled` | `bool` | Enable the rule on deploy (default: `true`) |
| `threshold` | `object` | Threshold config (for threshold rules) |
| `alert_suppression` | `object` | Alert suppression config |
| `exceptions_list` | `list(object)` | Exception list references |
| `space_id` | `string` | Kibana space ID |

See `modules/detection_rule/variables.tf` for the full list of optional inputs
(indices, scheduling, ML job IDs, new terms fields, timeline, etc.).

| Output | Description |
|---|---|
| `rule_id` | Kibana rule_id |
| `id` | Terraform resource ID |
| `name` | Rule name |

</details>

### `exception_list`

Wraps [`elasticstack_kibana_security_exception_list`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_list)
and [`elasticstack_kibana_security_exception_item`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item).
Creates **one** exception list container with child items per module call.
Use this for **shared** lists referenced by multiple rules.

<details>
<summary>Module interface</summary>

| Input | Type | Description |
|---|---|---|
| `list_id` | `string` | Unique list identifier |
| `name` | `string` | List display name |
| `description` | `string` | List description |
| `items` | `list(object)` | Exception items with entries |
| `space_id` | `string` | Kibana space ID |

See `modules/exception_list/variables.tf` for the full interface including
`namespace_type`, `os_types`, `tags`, and item-level options.

| Output | Description |
|---|---|
| `list_id` | Kibana list_id |
| `id` | Terraform resource ID |
| `item_ids` | Map of item_id → Kibana ID |

</details>

### `rule_exception_items`

Wraps [`elasticstack_kibana_security_exception_item`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item)
**only** — creates one or more exception items attached to an existing list.
Use this when you want analyst tuning items to live in a separate file from
the rule definition while still attaching to the rule's auto-created
rule-default list.

| Input | Type | Description |
|---|---|---|
| `list_id` | `string` | list_id of an existing exception list (typically `module.<rule>.rule_default_exception_list_id`) |
| `items` | `list(object)` | Exception items with entries (same schema as `exception_list.items`) |
| `space_id` | `string` | Kibana space ID |
| `namespace_type` | `string` | `single` (default) or `agnostic` |

| Output | Description |
|---|---|
| `item_ids` | Map of item_id → Kibana ID |
| `list_id` | Passthrough of the list the items were attached to |

---

## Adding a New Rule

> **🧙 Recommended:** Run `make new-rule` — an interactive wizard that prompts
> for every field in plain English, auto-generates the `.tf` file, and updates
> `outputs.tf`. No HCL knowledge required.

<details>
<summary>Manual steps</summary>

1. **Copy** the template (use the next available number):
   ```bash
   cp terraform/custom_rules/_template.tf.example \
      terraform/custom_rules/006_my_new_rule.tf
   ```

2. **Edit** the new file — fill in the module block:
   ```hcl
   module "my_new_rule" {
     source = "../modules/detection_rule"

     name        = "My New Detection Rule"
     description = "Detects ..."
     type        = "query"
     query       = "event.action:something_suspicious"
     language    = "kuery"
     severity    = "medium"
     risk_score  = 50
     tags        = ["my-tag", "Team: CSSP"]  # Team tag required!
     space_id    = var.space_id

     # Simplified MITRE mapping — just IDs, module resolves names/URLs
     mitre_attack = [
       { tactic = "TA0001", techniques = ["T1190"], subtechniques = [] },
     ]
   }
   ```

3. **Register the output** in `terraform/custom_rules/outputs.tf`:
   ```hcl
   my_new_rule = module.my_new_rule.rule_id
   ```

4. **Test → Plan → Deploy:**
   ```bash
   make test && make plan && make apply
   ```

</details>

---

## Adding an Exception

Two patterns, pick the smallest scope that solves your problem:

| Scope | Where it lives | Resource | Use when |
|---|---|---|---|
| **Rule-scoped** *(production default)* | inline `rule_exceptions = [...]` on the rule, or [`terraform/rule_exceptions/`](terraform/rule_exceptions/) | `kibana_security_exception_item` attached to the rule's auto-created default list | Tuning **one** rule. Mirrors what the Kibana Rules UI writes when you click "Add rule exception". |
| **Shared list** | [`terraform/exceptions/`](terraform/exceptions/) | `kibana_security_exception_list` + child items | Suppression container referenced by **multiple** rules (e.g. trusted infrastructure). |

### Rule-scoped exceptions

Add an inline list directly to the rule. The `detection_rule` module
auto-creates a per-rule exception list and attaches it.

```hcl
module "brute_force_login" {
  source = "../modules/detection_rule"
  # … existing fields …

  rule_exceptions = [
    {
      item_id     = "vuln-scanner"
      name        = "Authorized vulnerability scanner"
      description = "Quarterly scanner deliberately probes auth endpoints."
      tags        = ["false-positive-reduction"]
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

To keep the rule file lean while analysts add tuning items, drop a file in
[`terraform/rule_exceptions/`](terraform/rule_exceptions/) instead and reference the rule's
auto-generated list:

```hcl
module "brute_force_login_extras" {
  source   = "../modules/rule_exception_items"
  list_id  = var.rule_default_lists["brute_force_login"]
  space_id = var.space_id

  items = [ /* … kibana_security_exception_item entries … */ ]
}
```

`rule_default_lists` is wired automatically from
[terraform/custom_rules/outputs.tf](terraform/custom_rules/outputs.tf) by the root module.

### Shared exception list

> **🧙 Recommended:** Run `make new-exception` — an interactive wizard that
> walks you through creating a shared exception list with items.

<details>
<summary>Manual steps</summary>

1. **Copy** the template:
   ```bash
   cp terraform/exceptions/_template.tf.example \
      terraform/exceptions/005_my_exception.tf
   ```

2. **Edit** the new file:
   ```hcl
   module "my_exception" {
     source = "../modules/exception_list"

     list_id     = "my-exceptions"
     name        = "My Exception List"
     description = "Exceptions for ..."
     space_id    = var.space_id

     items = [
       {
         item_id     = "trusted-process"
         name        = "Trusted Process"
         description = "Skip alerts for trusted-process.exe"
         entries = [{
           field    = "process.name"
           type     = "match"
           operator = "included"
           value    = "trusted-process.exe"
         }]
       }
     ]
   }
   ```

3. **Register the output** in `terraform/exceptions/outputs.tf`:
   ```hcl
   my_exception = module.my_exception.list_id
   ```

4. **Test → Plan → Deploy:**
   ```bash
   make test && make plan && make apply
   ```

</details>

---

## Importing a GUI-Created Rule

Detection engineers who prototype rules in the Kibana GUI can bring them into
Terraform/Git with a single command:

```bash
# List all rules in Kibana
make list-rules

# Import by name (partial match)
make import-rule NAME="Password Change"
```

The script generates a `.tf` file in `custom_rules/` with both the `rule_id`
and the internal Kibana `id` in the header (you need the latter for
`terraform import`). Follow the printed next-steps:

1. Review and edit the generated file
2. Add to `outputs.tf`
3. `cd terraform && terraform init`
4. `terraform import` using the **internal Kibana `id`** (not the `rule_id`)
5. `terraform plan` to verify

> ⚠️ **Kibana has two different UUIDs per rule.** The `rule_id` is the API
> identifier used in queries. The `id` (internal document ID) is what the
> Terraform provider uses. The import script prints both.

### Brownfield Migration (Bulk Import)

For non-greenfield environments — where you already have a heavy operational
config in Kibana that needs to be "Terraformized" — see the dedicated
[IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md) for the phased
rollout (snapshot → parallel codify → shadow run → cutover → drift loop).

The bulk importer covers **custom detection rules**, **shared exception
lists**, and **rule-scoped exception items** in a single pass. Endpoint
lists are intentionally excluded.

```bash
# Phase 0 — fetch + cache only, render nothing
make bulk-import-dump

# Phase 1 — full pipeline (fetch + render .tf + import blocks)
make bulk-import

# Re-render from a cached dump without re-hitting Kibana
make bulk-import-from-cache DUMP_ID=2026-05-01

# Inspect what would be written, change nothing
make bulk-import-dry
```

Outputs:

- `.tf` files under [terraform/custom_rules/](terraform/custom_rules/),
  [terraform/exceptions/](terraform/exceptions/), and
  [terraform/rule_exceptions/](terraform/rule_exceptions/)
- A generated [terraform/imports.tf](terraform/) with Terraform 1.5 `import {}`
  blocks (delete after the first successful apply)
- A fallback [scripts/import.generated.sh](scripts/) with equivalent
  `terraform import` CLI commands

---

## Unit Testing

The pytest suite in `tests/test_rules.py` validates rule and exception
definitions **before** they reach Terraform — catching structural errors at the
PR stage.

<details>
<summary>Test coverage details</summary>

| Test | What it checks |
|---|---|
| Required fields | Every rule has name, description, type, severity, risk_score |
| Team tag | Every rule has a `Team: <name>` tag |
| MITRE mapping | Every rule maps to ≥1 ATT&CK tactic (via `threat` or `mitre_attack`) |
| Risk score range | 0–100 |
| Severity values | low / medium / high / critical |
| Rule types | Supported Elastic type |
| Query presence | Query-based rules include a query field |
| Exception structure | Lists & items have required fields and entries |

</details>

```bash
make test              # Quick run
make test-verbose      # Full output with tracebacks
```

---

## CI/CD Pipeline

The pipeline lives in [.gitlab-ci.yml](.gitlab-ci.yml) and runs on **dedicated
self-hosted GitLab Runners** with **AWS S3** for both Terraform remote state
and the runner's distributed cache.

### Pipeline stages

| Stage | Jobs | Trigger |
|---|---|---|
| `test` | `pytest`, `terraform:fmt`, `terraform:validate` | MRs and pushes to `main` |
| `plan` | `terraform:plan` (artifact `tfplan`), `terraform:plan-summary` | MRs and pushes to `main` |
| `apply` | `terraform:apply` (manual approval, `resource_group: production-apply`) | `main` only |

### Required CI/CD variables

| Variable | Purpose |
|---|---|
| `AWS_DEFAULT_REGION` | AWS region of the state bucket |
| `TF_STATE_BUCKET` | S3 bucket holding the remote state (e.g. `elastic-dac-terraform`) |
| `TF_STATE_KEY` | Object key for the state file (e.g. `elastic-dac/terraform.tfstate`) |
| `RUNNER_TAG` | Tag on the dedicated runner (default `elastic-dac`) |
| `KIBANA_API_KEY` | Encoded API key (the `encoded` field returned by POST /_security/api_key) |
| `KIBANA_ENDPOINT` | Live Kibana URL (the value in your browser address bar; include scheme + port) |
| `GITLAB_TOKEN` | Project access token used by the upstream sync job to open MRs |
| `TF_AUTO_APPLY` | Safety gate — `"true"` exposes the manual-approval `terraform:apply` button on `main`; any other value (or unset) hides the job entirely. **Default: `"false"`** |

> **Apply safety gate.** During brownfield import and the Phase 2 parallel-run
> window described in [IMPLEMENTATION_STRATEGY.md](IMPLEMENTATION_STRATEGY.md),
> keep `TF_AUTO_APPLY="false"`. CI will run plan-only — no apply job is created,
> so there is nothing to click and nothing that can mutate Kibana. Flip to
> `"true"` only when you are ready to enforce config from `main`. The job is
> still `when: manual`, so a human still has to press the button — the gate is
> belt-and-suspenders, not a replacement for review.

> **AWS auth.** The runner's EC2 instance role provides credentials via IMDS;
> we deliberately do **not** plumb `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
> through GitLab. State locking is handled natively by S3
> (`use_lockfile = true`) — no DynamoDB table is required.

Full AWS provisioning, IAM policy, and runner registration are in
[.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md). Local-dev backend
remains the on-disk default until you copy `terraform/backend.tf.example` to
`terraform/backend.tf`.

### Dedicated runners + S3

- Runner registration uses `--locked --run-untagged=false --tag-list elastic-dac`
  so jobs are pinned to your fleet and never spill onto shared SaaS runners.
- The runner's `[runners.cache]` block points at an S3 bucket so multiple
  runner instances share the `.terraform/` plugin cache and pipeline
  artifacts (see
  [.gitlab/GITLAB_RUNNERS.md §2c](.gitlab/GITLAB_RUNNERS.md#2c-configure-the-s3-backed-cache)).
- Concurrent applies serialise via `resource_group: production-apply` plus
  the DynamoDB state lock.

---

## Upstream Rule Sync

A scheduled GitLab pipeline ([.gitlab/ci/sync-upstream.gitlab-ci.yml](.gitlab/ci/sync-upstream.gitlab-ci.yml))
pulls the latest from
[`elastic/detection-rules`](https://github.com/elastic/detection-rules), diffs
TOML rule files against the last sync point, and opens a Merge Request with a
rich changelog.

<details>
<summary>Sync details</summary>

### How it works

1. Clones/fetches the upstream `elastic/detection-rules` repo
2. Diffs TOML rule files since the last tracked SHA
3. Generates a timestamped changelog entry (new / modified / removed rules)
4. Opens a Merge Request with the changelog for review

Configure the schedule via **Settings → CI/CD → Schedules** with the variable
`SYNC_UPSTREAM=true` (e.g. `0 8 * * 1`). Without that variable the job is
skipped, so it never runs on push pipelines.

### Running locally

```bash
make sync-upstream       # Full sync (updates tracking file)
make sync-upstream-dry   # Dry run (changelog only, no tracking update)
make sync-upstream-full  # First-time: catalog all existing upstream rules
```

On first run the script establishes a **baseline SHA** without generating a
massive changelog. Subsequent runs only report changes since that baseline.

</details>

---

## Make Targets

<details>
<summary>Full target reference</summary>

| Target | Description |
|---|---|
| `make creds-check` | 🔌 Verify env vars + reach the live cluster |
| `make plan` | Terraform plan |
| `make apply` | Terraform apply |
| `make destroy` | Terraform destroy (⚠️ destructive against the live cluster) |
| `make test` | Run pytest unit tests |
| `make test-verbose` | Tests with full output |
| `make ci` | Full CI pipeline locally (fmt → validate → test → plan) |
| `make fmt` | Format Terraform files |
| `make new-rule` | 🧙 Interactive wizard — create a new detection rule |
| `make new-exception` | 🧙 Interactive wizard — create a new exception list |
| `make list-rules` | List all detection rules in Kibana |
| `make import-rule` | Import a GUI-created rule into Terraform |
| `make cheatsheet` | 📋 Print quick-reference card to terminal |
| `make sync-upstream` | Sync from elastic/detection-rules |
| `make sync-upstream-dry` | Dry-run sync (no tracking update) |
| `make sync-upstream-full` | First-time full catalog sync |
| `make dac-export` | Export rules via detection-rules CLI |
| `make dac-import` | Import rules via detection-rules CLI |

</details>

The most common day-to-day targets:

```bash
make new-rule         # Create a rule (interactive)
make test             # Validate
make plan             # Preview
make apply            # Deploy
```

---

## References

- [WALKTHROUGH.md](WALKTHROUGH.md) — Practitioner how-to guide for everyday detection-engineering tasks
- [.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md) — AWS S3 + dedicated runner provisioning guide
- [MITRE ATT&CK Lookup](terraform/modules/detection_rule/mitre_lookup.tf) — All supported tactic/technique/subtechnique IDs
- [Elastic's DaC Engineer Guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features) — Primary methodology guide
- [DaC Reference Documentation](https://dac-reference.readthedocs.io/en/latest/) — Extended implementation guidance
- [elastic/detection-rules](https://github.com/elastic/detection-rules) — Elastic's open-source rule repo and CLI
- [elasticstack Terraform Provider](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs) — Provider documentation
- [Detection Rule Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_detection_rule) — TF resource docs
- [Exception List Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_list) — TF resource docs
- [Prebuilt Rules Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_install_prebuilt_rules) — TF resource docs

---

## License

This project is provided as a reference implementation for detection engineering
teams. Detection rule content is provided as examples only and should be adapted
to your environment.
