# Detection as Code — Elastic Stack + Terraform

> **A production-ready framework for managing Elastic Security detection rules,
> exceptions, and prebuilt rules using Terraform — following Elastic's
> [Detections as Code (DaC)](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features) methodology.**

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Workflow](#workflow)
- [Terraform Modules](#terraform-modules)
- [Custom Rules](#custom-rules)
- [Exception Lists](#exception-lists)
- [Unit Testing](#unit-testing)
- [CI/CD Pipeline](#cicd-pipeline)
- [Detection-Rules CLI Integration](#detection-rules-cli-integration)
- [Make Targets](#make-targets)
- [Adding a New Rule](#adding-a-new-rule)
- [Adding an Exception](#adding-an-exception)
- [References](#references)

---

## Overview

This project implements **Detection as Code (DaC)** for Elastic Security using
the [`elastic/elasticstack`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs)
Terraform provider. DaC applies software engineering practices — version control,
peer review, automated testing, and CI/CD pipelines — to security detection rule
management.

### What's included

| Component | Purpose |
|---|---|
| **Docker Compose** | Local Elasticsearch + Kibana stack for testing |
| **Terraform Modules** | Reusable modules for detection rules & exception lists |
| **Custom Rule Definitions** | 5 example rules (KQL, EQL, threshold) with MITRE ATT&CK mapping |
| **Exception Lists** | 4 exception containers with sample items for false-positive reduction |
| **Prebuilt Rules** | Optional install & enablement of Elastic's vendor-provided rules |
| **Pytest Suite** | Unit tests enforcing Team tags, MITRE mapping, field validation |
| **GitHub Actions** | CI/CD with `terraform plan` on PRs and `terraform apply` on merge |
| **detection-rules CLI** | Optional integration with Elastic's open-source DaC tooling |

### Key DaC Principles (from [Elastic's Guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features))

- **Version control** — All rules live in Git; every change is tracked
- **Peer review** — PRs gate all rule changes; plan output is posted as a comment
- **Automated testing** — Pytest validates rule structure, tags, MITRE mapping
- **Automated deployment** — Terraform apply on merge to `main`
- **Consistency** — Modules enforce standards across all rules
- **Team routing** — `Team: <name>` tags on every rule for SOC triage routing

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
                                    │  │ Elasticsearch:9200 │  │
                                    │  │ Kibana:5601        │  │
                                    │  │ Detection Engine   │  │
                                    │  └────────────────────┘  │
                                    └──────────────────────────┘
```

---

## Project Structure

```
elastic/
├── .github/
│   └── workflows/
│       └── detection-as-code.yml      # GitHub Actions CI/CD pipeline
├── terraform/
│   ├── main.tf                        # Provider config + child module calls
│   ├── variables.tf                   # Root variables
│   ├── outputs.tf                     # Root outputs
│   ├── prebuilt_rules.tf              # Elastic prebuilt rule management
│   ├── terraform.tfvars.example       # Example variable values
│   ├── modules/
│   │   ├── detection_rule/            # Reusable module: one detection rule
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   └── exception_list/            # Reusable module: one exception list
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   ├── custom_rules/                  # ← One .tf file per detection rule
│   │   ├── _providers.tf              #   Provider inheritance
│   │   ├── _template.tf.example       #   Copy-paste starter for new rules
│   │   ├── variables.tf               #   Shared inputs (space_id, tags)
│   │   ├── outputs.tf                 #   Aggregated rule outputs
│   │   ├── 001_brute_force_login.tf
│   │   ├── 002_suspicious_powershell_encoded.tf
│   │   ├── 003_lateral_movement_remote_services.tf
│   │   ├── 004_dns_exfiltration.tf
│   │   └── 005_suspicious_cron_creation.tf
│   └── exceptions/                    # ← One .tf file per exception list
│       ├── _providers.tf
│       ├── _template.tf.example
│       ├── variables.tf
│       ├── outputs.tf
│       ├── 001_trusted_infrastructure.tf
│       ├── 002_approved_powershell.tf
│       ├── 003_dns_allowlist.tf
│       └── 004_approved_cron.tf
├── tests/
│   ├── test_rules.py                  # Pytest unit tests for rules
│   └── requirements.txt               # Python test dependencies
├── scripts/
│   ├── setup.sh                       # Bootstrap the lab environment
│   ├── teardown.sh                    # Destroy everything
│   ├── validate.sh                    # Quick health check
│   └── dac-sync.sh                    # detection-rules CLI integration
├── docker-compose.yml                 # Elasticsearch + Kibana containers
├── Makefile                           # Shortcut targets
├── pytest.ini                         # Pytest configuration
├── .env.example                       # Environment variable template
├── .gitignore
└── README.md                          # This file
```

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| [Docker](https://docs.docker.com/get-docker/) | 20+ | Run Elasticsearch + Kibana locally |
| [Terraform](https://developer.hashicorp.com/terraform/downloads) | ≥ 1.5 | Infrastructure as Code engine |
| [Python](https://www.python.org/) | ≥ 3.10 | Run unit tests |
| [Make](https://www.gnu.org/software/make/) | any | Task runner (optional) |
| [detection-rules](https://github.com/elastic/detection-rules) | latest | CLI import/export (optional) |

---

## Quick Start

### 1. Clone and configure

```bash
git clone <your-repo-url> elastic
cd elastic
cp .env.example .env          # Review and adjust credentials
```

### 2. Bootstrap the lab

```bash
make setup
# This starts Docker, configures passwords, and runs terraform init
```

### 3. Run unit tests

```bash
make test
```

### 4. Preview changes

```bash
make plan
```

### 5. Deploy rules

```bash
make apply
```

### 6. Verify deployment

```bash
make validate-lab
```

### 7. Open Kibana

Navigate to http://localhost:5601 → **Security** → **Rules** to see your
deployed detection rules and exceptions.

---

## Workflow

### Local Development

```
Copy _template.tf.example → terraform/custom_rules/my_rule.tf
         │
         ▼
    make test          ← Pytest validates rule structure
         │
         ▼
    make plan          ← Preview Terraform changes
         │
         ▼
    make apply         ← Deploy to local Docker stack
         │
         ▼
    make validate-lab  ← Verify rules in Kibana
```

### CI/CD (Pull Request)

```
Push branch → Open PR
         │
         ▼
    GitHub Actions triggers
         │
    ┌────┴─────────────────┐
    │ terraform fmt -check │
    │ terraform validate   │
    │ terraform plan       │
    └────┬─────────────────┘
         │
         ▼
    Plan output posted as PR comment
```

### CI/CD (Merge to main)

```
PR merged to main
         │
         ▼
    terraform apply -auto-approve
         │
         ▼
    Rules deployed to Elastic Security
```

---

## Terraform Modules

### `detection_rule`

Wraps [`elasticstack_kibana_security_detection_rule`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_detection_rule).
Creates **one** detection rule per module call — designed to be called from
individual `.tf` files in `custom_rules/`.

| Input | Type | Description |
|---|---|---|
| `name` | `string` | Rule display name |
| `description` | `string` | Rule description |
| `type` | `string` | Rule type (query, eql, esql, threshold, new_terms, threat_match, machine_learning) |
| `query` | `string` | Detection query (KQL or EQL) |
| `language` | `string` | Query language (kuery, lucene, eql, esql) |
| `severity` | `string` | low / medium / high / critical |
| `risk_score` | `number` | 0–100 |
| `tags` | `list(string)` | Tags including Team: tag |
| `threat` | `list(object)` | MITRE ATT&CK mapping |
| `space_id` | `string` | Kibana space ID |
| `enabled` | `bool` | Enable the rule on creation (default: true) |

| Output | Description |
|---|---|
| `rule_id` | Kibana rule_id |
| `id` | Terraform resource ID |
| `name` | Rule name |

### `exception_list`

Wraps [`elasticstack_kibana_security_exception_list`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_list) and [`elasticstack_kibana_security_exception_item`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item).
Creates **one** exception list (with child items) per module call.

| Input | Type | Description |
|---|---|---|
| `list_id` | `string` | Unique list identifier |
| `name` | `string` | List display name |
| `description` | `string` | List description |
| `items` | `list(object)` | Exception items with entries |
| `space_id` | `string` | Kibana space ID |

| Output | Description |
|---|---|
| `list_id` | Kibana list_id |
| `id` | Terraform resource ID |
| `item_ids` | Map of item name → Kibana item_id |

---

## Custom Rules

Each detection rule lives in its own `.tf` file inside
[`terraform/custom_rules/`](terraform/custom_rules/). Each file contains a
single `module` block that calls the reusable `detection_rule` module. This
scales cleanly to 200+ rules — engineers copy
[`_template.tf.example`](terraform/custom_rules/_template.tf.example) and fill
in their rule parameters.

### Included example rules

| # | Name | Type | Severity | MITRE Tactic |
|---|---|---|---|---|
| 1 | Brute-Force Login Attempts | threshold | high | Credential Access (T1110) |
| 2 | Suspicious PowerShell Encoded Command | query | high | Execution (T1059.001) |
| 3 | Lateral Movement via Remote Service Creation | eql | critical | Lateral Movement (T1021) |
| 4 | Potential Data Exfiltration over DNS | query | medium | Exfiltration (T1048) |
| 5 | Suspicious Cron Job Created | query | medium | Persistence (T1053.003) |

### Team tag convention

Per [Elastic's DaC guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features),
every custom rule includes a `Team: <team_name>` tag for SOC routing:

```hcl
tags = ["windows", "powershell", "Team: Threat Intel"]
```

This is enforced by the pytest test suite (see [Unit Testing](#unit-testing)).

---

## Exception Lists

Each exception list lives in its own `.tf` file inside
[`terraform/exceptions/`](terraform/exceptions/). Each file contains a single
`module` block calling the `exception_list` module. Copy
[`_template.tf.example`](terraform/exceptions/_template.tf.example) to add a
new list.

### Included example exceptions

| List | Items | Purpose |
|---|---|---|
| Trusted Internal Infrastructure | LB health checks, monitoring svc account | Suppress auth-failure false positives |
| Approved PowerShell Automation | SCCM client, Intune management | Suppress encoded PS false positives |
| DNS Allowlist | CDN domains, SaaS domains | Suppress DNS tunnel false positives |
| Approved Cron Jobs | deploy user | Suppress cron persistence false positives |

---

## Unit Testing

The pytest test suite in [`tests/test_rules.py`](tests/test_rules.py) validates
rule definitions **before** they reach Terraform, catching errors at the PR
stage.

### Test coverage

| Test Class | What it checks |
|---|---|
| `TestRequiredFields` | Every rule has name, description, type, severity, risk_score |
| `TestTeamTag` | Every rule has a `Team: <team_name>` tag |
| `TestMitreMapping` | Every rule maps to ≥1 MITRE ATT&CK tactic with valid ID |
| `TestRiskScore` | Risk score is between 0–100 |
| `TestSeverity` | Severity is low/medium/high/critical |
| `TestRuleType` | Rule type is a supported Elastic type |
| `TestQueryPresence` | Query-based rules have a query field |
| `TestExceptionLists` | Exception lists & items have required fields and entries |

### Running tests

```bash
make test              # Quick run
make test-verbose      # Full output with tracebacks
```

---

## CI/CD Pipeline

The GitHub Actions workflow at [`.github/workflows/detection-as-code.yml`](.github/workflows/detection-as-code.yml)
implements a two-stage pipeline:

### Stage 1: Plan (on every PR)

1. `terraform fmt -check` — Enforce formatting
2. `terraform init` — Initialise providers
3. `terraform validate` — Validate HCL syntax
4. `terraform plan` — Generate execution plan
5. **Comment** plan output on the PR for peer review

### Stage 2: Apply (on merge to `main`)

1. Download the plan artifact from Stage 1
2. `terraform apply` — Deploy rules to Elastic Security

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `ELASTICSEARCH_USERNAME` | Elasticsearch username |
| `ELASTICSEARCH_PASSWORD` | Elasticsearch password |
| `ELASTICSEARCH_ENDPOINTS` | Comma-separated ES endpoints |
| `KIBANA_USERNAME` | Kibana username |
| `KIBANA_PASSWORD` | Kibana password |
| `KIBANA_ENDPOINT` | Kibana URL |

---

## Upstream Rule Sync

A **weekly GitHub Action** automatically pulls the latest from
[`elastic/detection-rules`](https://github.com/elastic/detection-rules), diffs
the TOML rule files against the last sync point, and opens a PR with a rich
changelog.

### How it works

```
elastic/detection-rules (GitHub)
         │
    weekly cron (Monday 08:00 UTC)
    or manual workflow_dispatch
         │
         ▼
  scripts/sync_upstream_rules.py
         │
    ┌─────┴──────────────────────────┐
    │ 1. Clone/fetch upstream repo   │
    │ 2. Diff TOML files vs last SHA │
    │ 3. Parse rule metadata         │
    │ 4. Generate changelog entry    │
    │ 5. Update tracking file        │
    └─────┬──────────────────────────┘
         │
         ▼
  PR opened with:
    • UPSTREAM_CHANGELOG.md (prepended entry)
    • .detection-rules-sync (updated SHA)
```

### Changelog format

Each sync generates a timestamped entry in `UPSTREAM_CHANGELOG.md` with:

- **New rules** — name, type, severity, MITRE ATT&CK tactic(s), file path
- **Modified rules** — same detail columns for changed rules
- **Removed rules** — file paths of deleted rules

### Running locally

```bash
make sync-upstream       # Full sync (updates tracking file)
make sync-upstream-dry   # Dry run (changelog only, no tracking update)
make sync-upstream-full  # First-time: catalog all existing upstream rules
```

### First-time setup

On the first run, the script establishes a **baseline SHA** without generating
a massive changelog of 1000+ existing rules. Subsequent runs will only report
changes since that baseline. Use `--first-sync-full` if you want the initial
full catalog.

---

## Detection-Rules CLI Integration

For teams that also use Elastic's [`detection-rules`](https://github.com/elastic/detection-rules)
Python CLI (the same tooling Elastic uses internally), we provide an integration
script at [`scripts/dac-sync.sh`](scripts/dac-sync.sh).

This is **complementary** to the Terraform approach — useful for:
- Bulk exporting existing rules from Kibana to TOML files
- Importing TOML-formatted rules alongside Terraform-managed ones
- Leveraging Elastic's built-in rule validation and schema checking

```bash
# Export custom rules from Kibana to local TOML files
make dac-export

# Import local TOML rules to Kibana
make dac-import

# Initialise a custom rules directory for the CLI
make dac-setup
```

---

## Make Targets

| Target | Description |
|---|---|
| `make setup` | Full lab bootstrap (Docker + Terraform init) |
| `make teardown` | Destroy everything |
| `make plan` | Terraform plan |
| `make apply` | Terraform apply |
| `make destroy` | Terraform destroy |
| `make test` | Run pytest unit tests |
| `make validate-lab` | Health check (ES, Kibana, rules, exceptions) |
| `make ci` | Full CI pipeline locally (fmt → validate → test → plan) |
| `make docker-up` | Start Docker stack only |
| `make docker-down` | Stop Docker stack |
| `make docker-logs` | Follow Docker logs |
| `make fmt` | Format Terraform files |
| `make new-rule` | 🧙 Interactive wizard — create a new detection rule |
| `make new-exception` | 🧙 Interactive wizard — create a new exception list |
| `make cheatsheet` | 📋 Print quick-reference card to terminal |
| `make sync-upstream` | Sync from elastic/detection-rules and update changelog |
| `make sync-upstream-dry` | Dry-run sync (no tracking file update) |
| `make sync-upstream-full` | First-time sync cataloging all upstream rules |
| `make dac-export` | Export rules via detection-rules CLI |
| `make dac-import` | Import rules via detection-rules CLI |

---

## Adding a New Rule

> **🧙 Recommended:** Run `make new-rule` — an interactive wizard that prompts
> for every field, auto-generates the `.tf` file, and updates `outputs.tf` for
> you. No HCL editing required. The manual steps below are an alternative.

<details>
<summary>Manual steps (click to expand)</summary>

1. **Copy** the template (use the next available number):
   ```bash
   cp terraform/custom_rules/_template.tf.example \
      terraform/custom_rules/006_my_new_rule.tf
   ```

2. **Edit** the new file — fill in the module block:
   ```hcl
   module "rule_my_new_rule" {
     source = "../modules/detection_rule"

     name        = "My New Detection Rule"
     description = "Detects ..."
     type        = "query"
     query       = "event.action:something_suspicious"
     language    = "kuery"
     severity    = "medium"
     risk_score  = 50
     tags        = ["my-tag", "Team: My Team"]  # Team tag required!
     space_id    = var.space_id

     threat = [{
       tactic = {
         id        = "TA0001"
         name      = "Initial Access"
         reference = "https://attack.mitre.org/tactics/TA0001/"
       }
       technique = []
     }]
   }
   ```

3. **Register the output** — add an entry to `terraform/custom_rules/outputs.tf`:
   ```hcl
   my_new_rule = module.rule_my_new_rule.rule_id
   ```

4. **Run tests** to validate: `make test`
5. **Preview**: `make plan`
6. **Deploy**: `make apply` (or push a PR for CI/CD)

</details>

---

## Adding an Exception

> **🧙 Recommended:** Run `make new-exception` — an interactive wizard that
> walks you through creating an exception list with items. No HCL editing
> required. The manual steps below are an alternative.

<details>
<summary>Manual steps (click to expand)</summary>

1. **Copy** the template (use the next available number):
   ```bash
   cp terraform/exceptions/_template.tf.example \
      terraform/exceptions/005_my_exception_list.tf
   ```

2. **Edit** the new file — fill in the module block:
   ```hcl
   module "exception_my_list" {
     source = "../modules/exception_list"

     list_id     = "my-exceptions"
     name        = "My Exception List"
     description = "Exceptions for ..."
     space_id    = var.space_id

     items = [
       {
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

3. **Register the output** — add an entry to `terraform/exceptions/outputs.tf`:
   ```hcl
   my_list = module.exception_my_list.list_id
   ```

4. **Link** the exception list to a rule via the `exceptions_list` attribute
5. **Test → Plan → Apply**

</details>

---

## References

- **[Elastic's DaC Engineer Guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features)** — The primary methodology guide for this project
- **[DaC Reference Documentation](https://dac-reference.readthedocs.io/en/latest/)** — Elastic's extended implementation guidance
- **[elastic/detection-rules](https://github.com/elastic/detection-rules)** — Elastic's open-source rule repository and CLI
- **[elasticstack Terraform Provider](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs)** — Provider documentation
- **[Detection Rule Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_detection_rule)** — Terraform resource for detection rules
- **[Exception List Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_list)** — Terraform resource for exception lists
- **[Exception Item Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item)** — Terraform resource for exception items
- **[Prebuilt Rules Resource](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_install_prebuilt_rules)** — Install Elastic's vendor rules via Terraform
- **[Elastic DaC Slack Channel](https://elasticstack.slack.com/archives/C06TE19EP09)** — Community support
- **[Instruqt DaC Training](https://play.instruqt.com/elastic/invite/uqlknuayvxhy)** — Hands-on lab from Elastic

---

## License

This project is provided as a reference implementation for detection engineering
teams. Detection rule content is provided as examples only and should be adapted
to your environment.
