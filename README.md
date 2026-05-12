# Detection as Code — Elastic Security + Terraform

> Manage Elastic Security detection rules, exceptions, and prebuilt-rule
> installs as code, using the [`elastic/elasticstack`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs)
> Terraform provider — per Elastic's
> [Detections as Code](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features) methodology.
>
> Two docs, on purpose: **this README** (architecture, what's where, how to
> deploy) and **[OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md)** (step-by-step
> playbooks for import, drift adoption, and net-new authoring).

---

## Contents

- [What this repo does](#what-this-repo-does)
- [What Terraform manages (and what it doesn't)](#what-terraform-manages-and-what-it-doesnt)
- [Repo layout](#repo-layout)
- [Prerequisites & environment constraints](#prerequisites--environment-constraints)
- [Getting started](#getting-started)
- [Day-to-day workflow](#day-to-day-workflow)
- [Brownfield migration (one-time bulk import)](#brownfield-migration-one-time-bulk-import)
- [CI/CD pipeline](#cicd-pipeline)
- [Modules](#modules)
- [Make targets (optional)](#make-targets-optional)
- [FAQ](#faq)
- [References](#references)

---

## What this repo does

| Component | Purpose |
|---|---|
| **Terraform modules** | Reusable modules for detection rules + exception lists ([terraform/modules/](terraform/modules/)) |
| **Custom rule definitions** | Example rules (KQL, EQL, threshold, threat-match) with MITRE ATT&CK mapping ([terraform/custom_rules/](terraform/custom_rules/)) |
| **Exception lists** | Shared and rule-scoped suppression containers ([terraform/exceptions/](terraform/exceptions/), [terraform/rule_exceptions/](terraform/rule_exceptions/)) |
| **Prebuilt rules** | Atomic install/update of Elastic's vendor rule pack ([terraform/prebuilt_rules.tf](terraform/prebuilt_rules.tf)) |
| **Pytest suite** | Enforces `Team:` tag, MITRE mapping, field validation ([tests/](tests/)) |
| **GitLab CI/CD** | MR `plan`, manual-approval `apply` on `main`, S3 backend, dedicated runners ([.gitlab-ci.yml](.gitlab-ci.yml)) |
| **Wizards** | `new_rule.sh` / `new_exception.sh` — non-coder rule authoring ([scripts/](scripts/)) |
| **GUI rule import** | Round-trip a Kibana-authored rule into Git/Terraform ([scripts/import_gui_rule.py](scripts/import_gui_rule.py)) |
| **Bulk brownfield import** | Render an entire live Kibana space (rules + exceptions) into `.tf` + `import {}` blocks ([scripts/bulk_import.py](scripts/bulk_import.py)) |
| **MITRE lookup** | Pass IDs only; the module resolves names + URLs ([terraform/modules/detection_rule/mitre_lookup.tf](terraform/modules/detection_rule/mitre_lookup.tf)) |
| **Upstream sync** | Weekly scheduled diff against `elastic/detection-rules` ([scripts/sync_upstream_rules.py](scripts/sync_upstream_rules.py)) |

### DaC principles (the short version)

- **Version control** every rule.
- **Peer review** every change (the MR plan is the review artifact).
- **Automated testing** (pytest) of rule structure, tags, MITRE.
- **Automated deployment** on merge to `main` (manual-approval `apply`).
- **Team routing** via mandatory `Team: <name>` tag.

---

## What Terraform manages (and what it doesn't)

A common worry is that DaC means managing *everything* in Terraform. It
doesn't. This framework splits the work along the seam where each tool is
strongest:

| Responsibility | Managed in | Why |
|---|---|---|
| Custom detection rules | Terraform ([custom_rules/](terraform/custom_rules/)) | Your org writes these — version control + peer review |
| Rule-scoped exception items | Terraform ([rule_exceptions/](terraform/rule_exceptions/) or inline) | Mirrors what the Kibana "Add rule exception" button writes |
| Shared exception lists | Terraform ([exceptions/](terraform/exceptions/)) | Multi-rule containers reviewed and tracked in Git |
| Prebuilt rule install/update | Terraform ([prebuilt_rules.tf](terraform/prebuilt_rules.tf)) | One atomic pack bump per release; no thousand-file MRs |
| Prebuilt rule **enablement** | Kibana Rules UI | Kibana already has bulk-action and tag-based filtering — no reason to replicate it in HCL |
| Alert triage, dashboards, timelines | Kibana | UI-native operational work, not infrastructure |

**The bottom line:** Terraform owns the things that benefit from review and
history (custom rules, suppressions, prebuilt pack version). Kibana owns the
operational decisions (which prebuilts to enable, triage, dashboards).
Detection engineers do **not** manage 1,400+ prebuilt rules as `.tf` files.

---

## Repo layout

```
elastic-dac/
├── .gitlab-ci.yml                       # Pipeline: test → plan → (manual) apply
├── .gitlab/
│   ├── GITLAB_RUNNERS.md                # AWS S3 + dedicated runner setup
│   └── ci/sync-upstream.gitlab-ci.yml   # Scheduled upstream-sync pipeline
├── terraform/
│   ├── main.tf                          # Provider + backend + child module calls
│   ├── backend.tf.example               # Copy → backend.tf to enable S3 state
│   ├── prebuilt_rules.tf                # Elastic prebuilt pack management
│   ├── modules/
│   │   ├── detection_rule/              # One rule (+ optional inline exceptions)
│   │   ├── exception_list/              # Shared list + items
│   │   └── rule_exception_items/        # Items attached to an existing list
│   ├── custom_rules/                    # One numbered .tf per detection rule
│   ├── exceptions/                      # One .tf per shared exception list
│   └── rule_exceptions/                 # One .tf per rule-scoped tuning bundle
├── scripts/                             # Wizards, importer, sync
│   ├── bulk_import.py                   # Brownfield import (API or NDJSON)
│   ├── import_gui_rule.py               # Single GUI-rule round-trip
│   ├── new_rule.sh / new_exception.sh   # Interactive wizards (bash)
│   └── importers/                       # NDJSON/HCL render helpers
├── tests/                               # Pytest validation suite
├── Makefile                             # Convenience shortcuts (optional)
├── OPERATIONS_RUNBOOK.md                # Day-to-day playbooks
└── README.md
```

**Convention:** rule/exception files use a numeric prefix (`001_`, `002_`, …)
for visual ordering. Copy `_template.tf.example` in any folder to add one,
or run the wizards (see [Day-to-day workflow](#day-to-day-workflow)).

---

## Prerequisites & environment constraints

| Tool | Version | Required? | Notes |
|---|---|---|---|
| Terraform | ≥ 1.10 | yes | Required for native S3 state locking |
| Python | ≥ 3.9 | yes | Runs pytest + helper scripts (pure stdlib; **no C compiler needed**) |
| `make` | any | **optional** | Just a wrapper around Python/Terraform/shell — see [Make targets](#make-targets-optional) for the equivalent direct commands |

> **No build tools required.** Everything ships as plain Python (stdlib only)
> and shell. There is nothing to compile, no native extensions, no `pip
> install` for the runtime. The optional `pytest` dev dependency
> ([tests/requirements.txt](tests/requirements.txt)) is also pure Python.
> If your workstation lacks GNU `make` or a C compiler, you can run every
> workflow using the direct `python3 scripts/...` / `terraform ...` commands
> shown throughout this doc and [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md).

### API access reality check

The provider, the importer, and `make creds-check` all need to reach the live
Kibana Detection Engine API. **This is not always available from a corporate
laptop** (mTLS at the edge, RBAC-restricted networks, blocked egress, etc.).
This repo is built to degrade gracefully when that's the case:

| You have… | You can do… | See |
|---|---|---|
| Laptop with API access | Everything: author, plan, apply, single-rule import | [Day-to-day workflow](#day-to-day-workflow) |
| Laptop **without** API access, runner **with** access | Author + render `.tf` offline; runner applies | [OPERATIONS_RUNBOOK.md → Playbook 1b](OPERATIONS_RUNBOOK.md#playbook-1b--offline-import-from-kibana-ndjson-export) |
| No API access from anywhere | Import from a Kibana **NDJSON export** as documentation only — apply must wait until any host can reach the API | [OPERATIONS_RUNBOOK.md → Playbook 1b](OPERATIONS_RUNBOOK.md#playbook-1b--offline-import-from-kibana-ndjson-export) |

### Source-format reality check

Elastic exposes rule content in **two** formats, and **JSON is not one of
them**:

- **NDJSON** — what Kibana's UI export and the Detection Engine API return
  (newline-delimited JSON; *not* a JSON array).
- **TOML** — what the upstream [`elastic/detection-rules`](https://github.com/elastic/detection-rules)
  CLI uses on disk.

Every importer/script in this repo accepts NDJSON (and produces HCL). If
someone hands you a `.json` file, it's almost certainly NDJSON with the wrong
extension — open it and check (one JSON object per line = NDJSON).

### Required env vars + credentials

- **`KIBANA_ENDPOINT`** — the URL in your Kibana browser tab (include scheme
  and port, e.g. `https://<host>:9243`).
- **`KIBANA_API_KEY`** — the `encoded` value from
  *Stack Management → API Keys*. The key needs Kibana **Security: All**
  privileges (or equivalent role descriptors). Keys snapshot privileges at
  creation time — if your role changed after, regenerate the key.

---

## Getting started

```bash
git clone <your-repo-url> elastic-dac
cd elastic-dac

export KIBANA_ENDPOINT="https://<deployment>.kb.<region>.aws.elastic-cloud.com:9243"
export KIBANA_API_KEY="<encoded API key>"

# Verify connectivity before anything else
python3 -c "import os,urllib.request,ssl; \
  r=urllib.request.Request(os.environ['KIBANA_ENDPOINT']+'/api/detection_engine/rules/_find?per_page=1', \
    headers={'Authorization':'ApiKey '+os.environ['KIBANA_API_KEY']}); \
  print(urllib.request.urlopen(r, context=ssl.create_default_context()).status)"
# → 200
```

(`make creds-check` does the same thing if you have `make`.)

Initialise Terraform — copy [terraform/backend.tf.example](terraform/backend.tf.example)
to `backend.tf` to switch on S3 remote state, then:

```bash
cd terraform
terraform init \
  -backend-config="bucket=$TF_STATE_BUCKET" \
  -backend-config="key=$TF_STATE_KEY" \
  -backend-config="region=$AWS_DEFAULT_REGION" \
  -backend-config="use_lockfile=true" \
  -backend-config="encrypt=true"
```

Run tests, preview, deploy:

```bash
python3 -m pytest -q                                 # or: make test
terraform -chdir=terraform plan                      # or: make plan
terraform -chdir=terraform apply                     # or: make apply
```

Verify in Kibana: **Security → Rules** for deployed rules,
**Security → Rules → Shared Exception Lists** for shared exceptions.

---

## Day-to-day workflow

```
edit / wizard           →  python3 -m pytest -q    →  terraform plan  →  MR  →  apply on merge
(custom_rules/*.tf)        (validate structure)       (preview diff)              (manual approval)
```

### Author a new rule

```bash
bash scripts/new_rule.sh        # interactive wizard; no HCL knowledge needed
# OR copy the template manually:
cp terraform/custom_rules/_template.tf.example \
   terraform/custom_rules/00N_<short_name>.tf
```

Fill in `name`, `description`, `type`, `query`, `severity`, `risk_score`,
`tags` (**must** include a `Team:` tag), and `mitre_attack` (IDs only — the
module resolves names + URLs). Register the output in
[terraform/custom_rules/outputs.tf](terraform/custom_rules/outputs.tf), then
`terraform -chdir=terraform init` (required when adding a new module block)
and run `pytest` + `plan` + `apply`.

### Author an exception

Two patterns — pick the smallest scope that solves your problem:

| Scope | Where | When |
|---|---|---|
| Rule-scoped *(default)* | Inline `rule_exceptions = [...]` on the rule, or a file in [terraform/rule_exceptions/](terraform/rule_exceptions/) | Tuning **one** rule. Mirrors the Kibana "Add rule exception" button. |
| Shared list | A file in [terraform/exceptions/](terraform/exceptions/) | Container referenced by **multiple** rules (e.g. trusted infrastructure). |

Wizard: `bash scripts/new_exception.sh`. Manual: copy `_template.tf.example`
in the appropriate folder.

### Import a GUI-built rule

```bash
python3 scripts/import_gui_rule.py --list                  # browse
python3 scripts/import_gui_rule.py --name "Password Change"
```

Generates a `.tf` in `custom_rules/` with **both** Kibana IDs in the header.
Follow the printed steps — note that `terraform import` takes the **internal
Kibana `id`**, not the `rule_id`.

---

## Brownfield migration (one-time bulk import)

For non-greenfield environments with an existing heavy Kibana config, see
[OPERATIONS_RUNBOOK.md → Playbook 1](OPERATIONS_RUNBOOK.md#playbook-1--brownfield-import).
The phased approach in short:

| Phase | What happens | Mutates Kibana? |
|---|---|---|
| **0 — Snapshot** | Export saved-objects NDJSON as rollback insurance; soft-freeze shared exception lists. | No |
| **1 — Codify** | `python3 scripts/bulk_import.py` (or `--from-export`) renders `.tf` + Terraform 1.5 `import {}` blocks. | No |
| **2 — Shadow run** | `TF_AUTO_APPLY="false"` — CI runs `plan` only. Nightly drift opens MRs for UI-authored changes. | No |
| **3 — Cutover** | Set `TF_AUTO_APPLY="true"`. First post-cutover `apply` **must** be a no-op (`0/0/0`). If it isn't, abort + revert. | Yes (no-op apply) |
| **4 — Steady state** | UI changes flow back as `drift:` MRs. State is authoritative. | Yes (via MR/apply) |

The importer covers **custom detection rules**, **shared exception lists**,
and **rule-scoped exception items** in a single pass. Prebuilt
(`immutable: true`) rules and `endpoint_list` are deliberately excluded — see
[FAQ](#faq).

**`terraform import` alone isn't enough.** It writes state but no HCL; the
1.5 `import {}` block with `-generate-config-out` is lossy for nested
attributes (`threat[]`, exception `entries`, the simplified `mitre_attack`
shape). So the bulk importer emits both the canonical `.tf` **and** matching
`import {}` blocks — one source of truth for "what does this rule look like
in HCL?"

The same generator powers single-resource drift adoption in Phase 4 (see
[OPERATIONS_RUNBOOK.md → Playbook 2](OPERATIONS_RUNBOOK.md#playbook-2--adopt-a-ui-created-rule-or-exception)).

---

## CI/CD pipeline

[.gitlab-ci.yml](.gitlab-ci.yml) runs on dedicated self-hosted GitLab Runners
with AWS S3 for both Terraform remote state and the runner cache.

| Stage | Jobs | Trigger |
|---|---|---|
| `test` | `pytest`, `terraform:fmt`, `terraform:validate` | MRs + pushes to `main` |
| `plan` | `terraform:plan` (artifact `tfplan`), `terraform:plan-summary` | MRs + pushes to `main` |
| `apply` | `terraform:apply` (manual approval, `resource_group: production-apply`) | `main` only, and only when `TF_AUTO_APPLY="true"` |

### Required CI/CD variables

| Variable | Purpose |
|---|---|
| `AWS_DEFAULT_REGION` | AWS region of the state bucket |
| `TF_STATE_BUCKET` | S3 bucket holding remote state |
| `TF_STATE_KEY` | Object key for the state (must live under the `t/` prefix per runner IAM) |
| `RUNNER_TAG` | Tag pinning jobs to the dedicated runner fleet (default `elastic-dac`) |
| `KIBANA_ENDPOINT` | Live Kibana URL |
| `KIBANA_API_KEY` | Encoded API key |
| `GITLAB_TOKEN` | Project access token used by the upstream-sync job |
| `TF_AUTO_APPLY` | Safety gate. `"true"` exposes the manual-approval apply job on `main`; anything else (or unset) **hides the job entirely**. Default: `"false"`. |

**Apply safety gate.** During brownfield import and the Phase-2 parallel-run
window, keep `TF_AUTO_APPLY="false"`. With the gate off, the `terraform:apply`
job is not created — there is nothing to click and nothing that can mutate
Kibana. Flip to `"true"` only when Phase 2 exit criteria are met. The job is
still `when: manual`, so a human still has to press the button — the gate is
belt-and-suspenders, not a replacement for review.

**AWS auth.** The runner's EC2 instance role provides credentials via IMDS;
we deliberately do **not** plumb `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
through GitLab. State locking is handled natively by S3
(`use_lockfile = true`) — no DynamoDB table required.

Full AWS provisioning, IAM policy, and runner registration are in
[.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md).

---

## Modules

### `detection_rule`

Wraps [`elasticstack_kibana_security_detection_rule`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_detection_rule).
One rule per module call. Key inputs: `name`, `description`, `type` (query /
eql / esql / threshold / new_terms / threat_match / machine_learning),
`query`, `language`, `severity`, `risk_score`, `tags` (must include `Team:`),
`mitre_attack` (simplified — IDs only) or `threat` (verbose), `enabled`,
`threshold`, `alert_suppression`, `exceptions_list`, `rule_exceptions`
(inline rule-default items), `space_id`. Full interface:
[modules/detection_rule/variables.tf](terraform/modules/detection_rule/variables.tf).

Outputs: `rule_id`, `id`, `name`, `rule_default_exception_list_id`.

### `exception_list`

Wraps [`elasticstack_kibana_security_exception_list`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_list)
and [`elasticstack_kibana_security_exception_item`](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs/resources/kibana_security_exception_item).
One shared list + its items per call. Inputs: `list_id`, `name`,
`description`, `items[]`, `space_id`. Outputs: `list_id`, `id`, `item_ids`.

### `rule_exception_items`

Items only — attaches to an existing list (typically a rule's auto-generated
default list). Use this when you want analyst tuning items to live in a
separate file from the rule definition. Inputs: `list_id`, `items[]`,
`space_id`, `namespace_type`.

---

## Make targets (optional)

The Makefile is a thin wrapper. Every target is one or two underlying
commands; if you don't have `make`, run them directly.

| Make target | Direct equivalent |
|---|---|
| `make creds-check` | `python3 scripts/import_gui_rule.py --list \| head -1` (any API call) |
| `make test` | `python3 -m pytest -q` |
| `make plan` | `terraform -chdir=terraform plan` |
| `make apply` | `terraform -chdir=terraform apply` |
| `make fmt` | `terraform -chdir=terraform fmt -recursive` |
| `make new-rule` | `bash scripts/new_rule.sh` |
| `make new-exception` | `bash scripts/new_exception.sh` |
| `make list-rules` | `python3 scripts/import_gui_rule.py --list` |
| `make import-rule NAME="..."` | `python3 scripts/import_gui_rule.py --name "..."` |
| `make bulk-import` | `python3 scripts/bulk_import.py` |
| `make bulk-import-dump` | `python3 scripts/bulk_import.py --dump-only` |
| `make bulk-import-from-cache DUMP_ID=…` | `python3 scripts/bulk_import.py --from-cache <id>` |
| `make bulk-import-from-export EXPORT=…` | `python3 scripts/bulk_import.py --from-export <path>` |
| `make sync-upstream` | `python3 scripts/sync_upstream_rules.py` |

---

## FAQ

### My Kibana space has 1,800+ rules but `bulk-import` only renders ~30. Is something broken?

No — that's exactly what the design intends. The number you saw is the
count of **custom** rules (the ones your team authored). The other ~1,770
are Elastic-prebuilt rules; they're managed by a different mechanism. See
the next two answers.

### Why aren't Elastic prebuilt rules rendered as individual `.tf` files?

Three reasons, each of which has bitten production teams:

1. **Upstream churn.** Elastic ships 50–200 prebuilt rule changes every
   release. If each lived as a `.tf` file, every Elastic release becomes a
   multi-hundred-file MR. People start rubber-stamping the diff. With the
   install resource, you bump a version variable and the pack updates
   atomically.
2. **`immutable: true` semantics.** Elastic marks prebuilts immutable on
   purpose — you cannot edit the query, severity, or threat mapping via API.
   Even if you imported one, every field you'd normally manage in the `.tf`
   would silently revert. Terraform would detect drift on every plan against
   fields it can't actually change.
3. **The fields you *do* control aren't on the rule body.** What you
   actually manage for prebuilts (suppression, tuning, enablement) lives
   elsewhere — see the next answer.

The bulk importer therefore drops `immutable: true` rules; the
[scripts/importers/rules.py](scripts/importers/rules.py) `filter_custom()`
helper enforces this in both the API and NDJSON paths.

### So where *are* prebuilts in the DaC strategy?

Prebuilts are still managed by Terraform — just as one resource representing
the whole pack, not 1,800 individual files:

| Decision | Where | Why |
|---|---|---|
| Install / don't install the pack | [terraform/prebuilt_rules.tf](terraform/prebuilt_rules.tf) (`install_prebuilt_rules` var) | Atomic bumps |
| Pin pack version | Provider version in [terraform/main.tf](terraform/main.tf) | Provider release coincides with pack version |
| Enable / disable a specific prebuilt | Kibana UI (Rules grid → Bulk actions) | Detection engineers iterate constantly during tuning |
| Suppress a false positive | [terraform/exceptions/](terraform/exceptions/) (shared) or [terraform/rule_exceptions/](terraform/rule_exceptions/) (rule-default) | Suppressions *are* code |

The **detection logic** of prebuilts is Elastic's; your **deployment,
suppression, and tuning** are in code. That's the "as code" part for them.

### Why does the importer use NDJSON and not JSON?

Because Kibana doesn't emit plain JSON for rules. Both the Detection Engine
API and the UI export return **NDJSON** (one JSON object per line). The
upstream rule repo uses **TOML**. JSON-array files don't exist in this
ecosystem; if you have one, it was hand-built and you should convert it to
NDJSON before feeding it to the importer.

### Can I run this without `make` or a C compiler?

Yes. Every workflow has a direct `python3` / `terraform` / `bash`
equivalent — see [Make targets](#make-targets-optional). The Python is
stdlib-only; there's nothing to compile.

### Can I force prebuilt enablement to be code-managed too?

Possible, but it's a separate design — requires maintaining a parallel rule-
activation list keyed by `rule_id`. Most teams find the friction outweighs
the benefit. If your org's compliance posture requires it (some DOD
environments do), open an issue and we can sketch the resource layout.

---

## References

- [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) — Step-by-step playbooks (brownfield import, drift adoption, net-new authoring)
- [.gitlab/GITLAB_RUNNERS.md](.gitlab/GITLAB_RUNNERS.md) — AWS S3 + dedicated runner provisioning
- [terraform/modules/detection_rule/mitre_lookup.tf](terraform/modules/detection_rule/mitre_lookup.tf) — Supported MITRE ATT&CK IDs
- [Elastic's DaC guide](https://www.elastic.co/security-labs/detection-as-code-timeline-and-new-features) — Methodology
- [DaC reference docs](https://dac-reference.readthedocs.io/en/latest/) — Extended guidance
- [`elastic/detection-rules`](https://github.com/elastic/detection-rules) — Upstream rule repo + CLI
- [`elasticstack` provider](https://registry.terraform.io/providers/elastic/elasticstack/latest/docs) — Provider docs
