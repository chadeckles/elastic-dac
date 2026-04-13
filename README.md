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
| **GitHub Actions** | CI/CD with `terraform plan` on PRs and `terraform apply` on merge |
| **Interactive Wizards** | `make new-rule` and `make new-exception` for non-coder detection engineers |
| **GUI Rule Import** | `make import-rule` brings Kibana-created rules into Git/Terraform |
| **MITRE ATT&CK Lookup** | ID-only MITRE mapping — module auto-resolves names and URLs |
| **Upstream Sync** | Weekly automated sync from Elastic's detection-rules repo |

### Key DaC Principles

Per [Elastic's DaC guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features):

- **Version control** — All rules live in Git; every change is tracked
- **Peer review** — PRs gate all rule changes; plan output is posted as a comment
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
| **Exception lists** | Terraform (`exceptions/`) | Suppression logic is critical context that should be reviewed and tracked in Git |
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
               │ PR → plan                        │ merge → apply
               ▼                                  ▼
┌──────────────────────┐            ┌──────────────────────────┐
│  GitHub Actions CI   │            │   GitHub Actions CD      │
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
├── .github/workflows/          # CI/CD pipelines
├── terraform/
│   ├── main.tf                 # Provider config + child module calls
│   ├── variables.tf            # Root variables
│   ├── outputs.tf              # Root outputs
│   ├── prebuilt_rules.tf       # Elastic prebuilt rule management
│   ├── modules/
│   │   ├── detection_rule/     # Reusable module: one detection rule
│   │   │   └── mitre_lookup.tf # MITRE ATT&CK ID → name/URL lookup maps
│   │   └── exception_list/     # Reusable module: one exception list + items
│   ├── custom_rules/           # One numbered .tf file per detection rule
│   └── exceptions/             # One numbered .tf file per exception list
├── tests/                      # Pytest unit tests
├── scripts/                    # Setup, teardown, sync, wizards, import
│   ├── import_gui_rule.py      # Import a Kibana GUI rule into Terraform
│   └── demo_cleanup.sh         # Reset environment between demo runs
├── docker-compose.yml          # Local dev stack (optional)
├── Makefile                    # Shortcut targets
├── DEMO_RUNBOOK.md             # Step-by-step demo walkthrough
└── README.md
```

**Convention:** Rule and exception files use a numbered prefix (`001_`, `002_`, …)
for visual ordering. Copy `_template.tf.example` in the respective directory to
add a new one, or use the interactive wizards (`make new-rule` / `make new-exception`).

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| [Terraform](https://developer.hashicorp.com/terraform/downloads) | ≥ 1.5 | Infrastructure as Code engine |
| [Python](https://www.python.org/) | ≥ 3.9 | Run unit tests |
| [Make](https://www.gnu.org/software/make/) | any | Task runner (optional) |

You'll also need network access to an **Elasticsearch** and **Kibana** instance
(cloud, on-prem, or local Docker).

---

## Getting Started

### 1. Clone and configure

```bash
git clone <your-repo-url> elastic
cd elastic
cp .env.example .env          # Review and adjust credentials
```

### 2. Initialise Terraform

```bash
# Point to your Elastic cluster (edit .env or terraform.tfvars)
cd terraform
terraform init
```

### 3. Run unit tests

```bash
make test
```

### 4. Preview and deploy

```bash
make plan                     # Review what will change
make apply                    # Deploy rules + exceptions
```

### 5. Verify in Kibana

Navigate to your Kibana instance → **Security** → **Rules** to see deployed
detection rules and exceptions.

<details>
<summary><strong>🐳 Local Demo with Docker</strong> (click to expand)</summary>

A `docker-compose.yml` is included for standing up a local single-node
Elasticsearch + Kibana stack for testing purposes.

```bash
make setup                    # Starts Docker stack + terraform init
make validate-lab             # Health check ES, Kibana, rules
make teardown                 # Destroy everything when done
```

Default credentials: `elastic` / `changeme` (see `.env.example`).

Kibana will be available at http://localhost:5601.

</details>

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

### CI/CD (Pull Request → Merge)

```
Push branch → Open PR
         │
    ┌────┴─────────────────┐
    │ terraform fmt -check │
    │ terraform validate   │
    │ terraform plan       │
    │ pytest tests         │
    └────┬─────────────────┘
         │
    Plan output posted as PR comment
         │
    PR merged to main
         │
         ▼
    terraform apply -auto-approve
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

> **🧙 Recommended:** Run `make new-exception` — an interactive wizard that
> walks you through creating an exception list with items. No HCL knowledge
> required.

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

GitHub Actions workflows in `.github/workflows/` implement the full DaC
lifecycle.

<details>
<summary>Pipeline details</summary>

### detection-as-code.yml

**On PR:** `terraform fmt -check` → `terraform init` → `terraform validate` →
`terraform plan` → post plan output as PR comment.

**On merge to `main`:** `terraform apply -auto-approve`.

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `ELASTICSEARCH_USERNAME` | Elasticsearch username |
| `ELASTICSEARCH_PASSWORD` | Elasticsearch password |
| `ELASTICSEARCH_ENDPOINTS` | Comma-separated ES endpoints |
| `KIBANA_USERNAME` | Kibana username |
| `KIBANA_PASSWORD` | Kibana password |
| `KIBANA_ENDPOINT` | Kibana URL |

</details>

---

## Upstream Rule Sync

A weekly GitHub Action pulls the latest from
[`elastic/detection-rules`](https://github.com/elastic/detection-rules), diffs
TOML rule files against the last sync point, and opens a PR with a rich
changelog.

<details>
<summary>Sync details</summary>

### How it works

1. Clones/fetches the upstream `elastic/detection-rules` repo
2. Diffs TOML rule files since the last tracked SHA
3. Generates a timestamped changelog entry (new / modified / removed rules)
4. Opens a PR with the changelog for review

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
| `make setup` | Full lab bootstrap (Docker + Terraform init) |
| `make teardown` | Destroy everything |
| `make plan` | Terraform plan |
| `make apply` | Terraform apply |
| `make destroy` | Terraform destroy |
| `make test` | Run pytest unit tests |
| `make test-verbose` | Tests with full output |
| `make validate-lab` | Health check (ES, Kibana, rules, exceptions) |
| `make ci` | Full CI pipeline locally (fmt → validate → test → plan) |
| `make fmt` | Format Terraform files |
| `make new-rule` | 🧙 Interactive wizard — create a new detection rule |
| `make new-exception` | 🧙 Interactive wizard — create a new exception list |
| `make list-rules` | List all detection rules in Kibana |
| `make import-rule` | Import a GUI-created rule into Terraform |
| `make demo-reset` | Reset environment between demo practice runs |
| `make cheatsheet` | 📋 Print quick-reference card to terminal |
| `make sync-upstream` | Sync from elastic/detection-rules |
| `make sync-upstream-dry` | Dry-run sync (no tracking update) |
| `make sync-upstream-full` | First-time full catalog sync |
| `make docker-up` | Start local Docker stack |
| `make docker-down` | Stop local Docker stack |
| `make docker-logs` | Follow Docker logs |
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

- [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) — Step-by-step demo walkthrough for screen recordings
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
