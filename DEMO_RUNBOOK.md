# Detection as Code — Demo Runbook

> **Purpose:** Step-by-step walkthrough for a live screen-recorded demo of the
> Detection-as-Code framework. Covers every evaluation scenario requested by
> the detection engineering team.
>
> **Prerequisites:** Local Elastic Stack running via `docker compose up -d`
> (or `make setup`), Terraform initialised (`make init`), existing rules
> deployed (`make apply`).

---

## Table of Contents

1. [Pre-Demo Setup](#1-pre-demo-setup)
2. [Demo 1 — Tour the Repo Structure](#2-demo-1--tour-the-repo-structure)
3. [Demo 2 — Create a New Custom Rule in Terraform](#3-demo-2--create-a-new-custom-rule-in-terraform)
4. [Demo 3 — Create a Rule in the Kibana GUI, Import into Terraform](#4-demo-3--create-a-rule-in-the-kibana-gui-import-into-terraform)
5. [Demo 4 — Add an Exception List (Without Touching the Rule)](#5-demo-4--add-an-exception-list-without-touching-the-rule)
6. [Demo 5 — Modify an Exception (Rule Logic Unchanged)](#6-demo-5--modify-an-exception-rule-logic-unchanged)
7. [Demo 6 — Install Prebuilt Rules via Terraform](#7-demo-6--install-prebuilt-rules-via-terraform)
8. [Demo 7 — Fork a Prebuilt Rule, Import the Custom Copy into Git](#8-demo-7--fork-a-prebuilt-rule-import-the-custom-copy-into-git)
9. [Demo 8 — Change a Query in Terraform and Redeploy](#9-demo-8--change-a-query-in-terraform-and-redeploy)
10. [Demo 9 — Convert a Rule to a Building Block](#10-demo-9--convert-a-rule-to-a-building-block)
11. [Demo 10 — The CI/CD Flow (PR → Plan → Merge → Apply)](#11-demo-10--the-cicd-flow-pr--plan--merge--apply)
12. [Post-Demo Cleanup](#12-post-demo-cleanup)

---

## 1. Pre-Demo Setup

Run these **before** hitting record. The demo should start with everything
healthy and some rules already deployed.

```bash
# Start the local Elastic Stack (also deploys baseline rules automatically)
make setup

# Open Kibana in a browser tab (keep it ready)
open http://localhost:5601/app/security/rules
```

**Confirm in Kibana:**
- Navigate to **Security → Rules** — you should see the 5 custom rules deployed
- Navigate to **Security → Rules → Shared Exception Lists** — you should see 4 exception lists

**Terminal tabs to have open:**
1. Project root (for `make` commands)
2. Editor with the repo open (VS Code)
3. Kibana in a browser

---

## 2. Demo 1 — Tour the Repo Structure

> **Goal:** Show the audience how the project is organised and where things live.

**In VS Code / terminal:**

```bash
# Show the high-level structure
tree -L 2 --dirsfirst

# Point out:
#   terraform/custom_rules/   → one .tf file per detection rule
#   terraform/exceptions/     → one .tf file per exception list
#   terraform/modules/        → reusable modules (detection_rule, exception_list)
#   terraform/main.tf         → provider config + module wiring
#   tests/                    → pytest unit tests
#   .github/workflows/        → CI/CD pipelines
```

**Open and walk through these files briefly:**

1. **`terraform/main.tf`** — Show the provider config (Elasticsearch + Kibana)
   and the two child module calls (`custom_rules`, `exceptions`).

2. **`terraform/custom_rules/001_brute_force_login.tf`** — Show an existing
   rule. Point out: module source, required fields (name, description, type,
   severity, risk_score, tags, threat), the `Team:` tag, the MITRE mapping.

3. **`terraform/modules/detection_rule/variables.tf`** — Show the module
   interface. Point out required vs optional variables.

4. **`terraform/exceptions/001_trusted_infrastructure.tf`** — Show an exception
   list with items and entries.

5. **`tests/test_rules.py`** — Show the pytest suite: required fields check,
   team tag enforcement, MITRE mapping validation, severity/risk range checks.

**Talking points:**
- "Every rule is a file in Git — full version history, peer review, rollback."
- "The module enforces consistency — every rule has the same structure."
- "Tests catch structural problems before anything hits Elastic."
- "Exceptions are separate from rules — you can update suppression logic
  without touching rule logic."

---

## 3. Demo 2 — Create a New Custom Rule in Terraform

> **Goal:** Show creating a brand-new custom rule entirely in code, testing it,
> and deploying it.

### Option A: Use the wizard (non-coder friendly)

```bash
make new-rule
```

Walk through the prompts:
- **Name:** `Suspicious Scheduled Task Creation`
- **Description:** `Detects creation of Windows scheduled tasks via schtasks.exe, often used for persistence.`
- **Type:** `query`
- **Severity:** `medium`
- **Risk score:** `55`
- **Language:** `kuery`
- **Query:** `process.name:"schtasks.exe" AND process.args:("/create" OR "/Create")`
- **Index patterns:** `winlogbeat-*,logs-endpoint.events.*`
- **Team:** `SOC`
- **MITRE Tactic:** `TA0003` (Persistence)
- **Technique:** `T1053` (Scheduled Task/Job)
- **Sub-technique:** `T1053.005` (Scheduled Task)
- **Enabled:** `no`

### Option B: Copy the template by hand

```bash
# Find the next number
ls terraform/custom_rules/[0-9]*.tf | sort | tail -1
# → 005_suspicious_cron_creation.tf

cp terraform/custom_rules/_template.tf.example \
   terraform/custom_rules/006_suspicious_scheduled_task.tf
```

Edit the file — fill in the module block with the values above.

### After creating the rule (either method):

```bash
# 1. Run unit tests — catches missing fields, bad tags, etc.
make test

# 2. Register the new module with Terraform
cd terraform && terraform init && cd ..
# → You should see: "- custom_rules.<your_module> in modules/detection_rule"
#
# ⚠️  This is required every time you add a new module block.
#    Without it, terraform plan will fail with "Module not installed".
#    Always run from the terraform/ directory, not the repo root.

# 3. Preview what Terraform will do
make plan
# → Show the output: "1 to add, 0 to change, 0 to destroy"

# 4. Deploy
make apply

# 4. Verify in Kibana
# → Navigate to Security → Rules → search for "Scheduled Task"
# → Show the rule appeared with correct severity, tags, MITRE mapping
```

**Talking point:** "From creation to deployed in Kibana — tested, reviewed, and
version-controlled. If this was a real workflow, this would go through a PR."

---

## 4. Demo 3 — Create a Rule in the Kibana GUI, Import into Terraform

> **Goal:** Show the "detection engineer builds a rule in the GUI, then we bring
> it into version control" workflow.

### Step 1: Create a rule manually in Kibana

1. Open **Kibana → Security → Rules → Create new rule**
2. Select **Custom query**
3. Fill in:
   - **Query:** `event.action:"user-password-changed" AND event.outcome:"success"`
   - **Index patterns:** `logs-*`
   - **Name:** `Password Change Detected`
   - **Description:** `Detects successful password changes that may indicate account takeover.`
   - **Severity:** `Medium`
   - **Risk score:** `40`
   - **MITRE:** Initial Access → Valid Accounts (T1078)
   - **Tags:** `Team: SOC`, `identity`, `account-takeover`
4. Click **Create & enable rule**
5. Confirm it appears in the rules list

### Step 2: Understand the two Kibana IDs

> ⚠️ **Critical gotcha — Kibana has TWO different IDs for every rule:**
>
> | ID | Example | Used for |
> |----|---------|----------|
> | `rule_id` | `b4f2c3c2-8be9-...` | Kibana API lookups, referenced in your `.tf` file |
> | `id` (internal document ID) | `6e5e94d2-9eab-...` | **`terraform import` — you MUST use this one** |
>
> If you use the wrong one, `terraform import` will fail with
> "Cannot import non-existent remote object", but `terraform apply` will
> fail with a **409 conflict** because the `rule_id` already exists.

You don't need to look these up manually — the import script fetches both
and prints them in the generated `.tf` header and in the next-steps output.

### Step 3: Generate the Terraform file

```bash
make import-rule NAME="Password Change"
```

This generates a `.tf` file in `terraform/custom_rules/`. Show the output.

### Step 4: Review and clean up the generated file

```bash
# Open the generated file (number will vary — check the script output)
cat terraform/custom_rules/007_password_change_detected.tf
```

**Show the audience the file header — it now includes both IDs:**

```
# rule_id:   b4f2c3c2-...   ← the Kibana API/query identifier
# kibana_id: 6e5e94d2-...   ← use THIS for terraform import
```

**Show the audience:** "The script generates a starting point — we always
review and clean it up. This is intentional. The detection engineer should
own the final version."

Edit if needed (fix tags, add false positives, triage notes, etc.).

### Step 5: Register in outputs.tf

Add the new module to `terraform/custom_rules/outputs.tf`:

```hcl
password_change_detected = module.password_change_detected.rule_id
```

### Step 6: Initialise the new module

Any time you add a new `module` block, Terraform needs to register it:

```bash
cd terraform && terraform init
```

You should see: `- custom_rules.password_change_detected in modules/detection_rule`

> **Common mistake:** Running `terraform init` from the repo root instead of
> `terraform/`. From the repo root it says "empty directory" — you need to be
> inside the `terraform/` folder.

### Step 7: Import into Terraform state

The import script printed the exact command — copy it from the terminal output.
It looks like this (your UUIDs will be different):

```bash
cd terraform

terraform import \
  'module.custom_rules.module.password_change_detected.elasticstack_kibana_security_detection_rule.this' \
  'default/<kibana_id>'
```

> ⚠️ **Use the `kibana_id` (internal document ID) — NOT the `rule_id`.**
> Both are printed in the generated `.tf` file header and in the script output.
> The `rule_id` is what Kibana uses for API lookups. The `kibana_id` is the
> Saved Object document ID that the Terraform provider uses internally.

```bash
# Verify — should show 0 to add, ≤1 to change, 0 to destroy
terraform plan
```

The "1 to change" is expected — Terraform will sync standard tags
(`detection-as-code`, `terraform-managed`) and module defaults (`author`,
`license`) onto the imported rule. That's the point — the framework
enforces consistency.

```bash
# Apply the minor drift
terraform apply -auto-approve
```

### Step 8: Verify in Kibana

Refresh the rules page — the rule should still be there, now with the standard
tags applied.

**Talking point:** "The rule already existed in Kibana. We told Terraform
'this resource is yours now.' From here forward, all changes go through Git.
The import script gives you the exact command — no hunting for IDs."

---

## 5. Demo 4 — Add an Exception List (Without Touching the Rule)

> **Goal:** Show that exception lists are independent resources — adding or
> modifying one does NOT change the detection rule's logic.

### Step 1: Create a new exception list

```bash
# Copy the template
cp terraform/exceptions/_template.tf.example \
   terraform/exceptions/005_password_change_service_accounts.tf
```

Edit the file:

```hcl
module "password_change_svc_accounts" {
  source = "../modules/exception_list"

  list_id     = "password-change-service-accounts"
  name        = "Password Change — Service Accounts"
  description = "Suppress password-change alerts for automated service accounts."
  type        = "detection"
  tags        = ["service-accounts", "false-positive-reduction"]

  items = [
    {
      item_id     = "svc-password-rotation"
      name        = "Automated Password Rotation"
      description = "CyberArk/Thycotic password rotation service accounts."
      tags        = ["cyberark"]
      entries = [
        {
          field    = "user.name"
          type     = "match"
          operator = "included"
          value    = "svc_password_rotation"
        }
      ]
    },
  ]

  space_id = var.space_id
}
```

### Step 2: Register in outputs

Add to `terraform/exceptions/outputs.tf`:
```hcl
password_change_svc_accounts = module.password_change_svc_accounts.list_id
```

### Step 3: Register the new module

```bash
cd terraform && terraform init && cd ..
```

> ⚠️ **Every new `module` block requires `terraform init`** — rules AND
> exceptions. Without it you'll get: `Error: Module not installed`.
> Always run from the `terraform/` directory.

### Step 4: Test and deploy

```bash
make test    # Validates structure
make plan    # Show: "1 to add" — only the exception list, NOT the rule
make apply
```

**Key moment for the screen recording:** Point at the plan output and say:
"Notice — we're adding 1 exception list and 1 exception item. Zero changes to
any detection rules. The exception is a standalone resource."

### Step 5: Verify in Kibana

Navigate to **Security → Rules → Shared Exception Lists** — show the new list.

---

## 6. Demo 5 — Modify an Exception (Rule Logic Unchanged)

> **Goal:** Show that editing an exception item (e.g., adding a second service
> account to the allowlist) only changes the exception — the rule stays
> untouched.

### Step 1: Edit the exception file

Open `terraform/exceptions/001_trusted_infrastructure.tf`.

Add a new item to the `items` list:

```hcl
    {
      item_id     = "nat-gateway"
      name        = "NAT Gateway"
      description = "NAT gateway generates auth noise from outbound traffic."
      tags        = ["network"]
      entries = [
        {
          field    = "source.ip"
          type     = "match"
          operator = "included"
          value    = "10.0.1.1"
        }
      ]
    },
```

### Step 2: Plan and show the diff

```bash
make plan
```

**Key moment:** The plan should show:
- `~ module.exceptions.module.trusted_infrastructure` — **1 changed** (new item)
- **0 changes** to any `custom_rules` resources

"We added a NAT gateway to the trusted infrastructure exception list. The
brute-force login rule that uses this exception? Completely untouched. The
exception is its own resource."

### Step 3: Deploy and verify

```bash
make apply
```

Check in Kibana → the exception list now has 3 items.

---

## 7. Demo 6 — Install Prebuilt Rules via Terraform

> **Goal:** Show that Terraform can install Elastic's out-of-the-box prebuilt
> rules with a single resource.

### Step 1: Show the prebuilt rules config

```bash
cat terraform/prebuilt_rules.tf
```

Walk through:
- `elasticstack_kibana_install_prebuilt_rules` resource
- Controlled by `var.install_prebuilt_rules` (default: `true`)
- "This installs and keeps prebuilt rules up to date. Enablement of individual
  prebuilt rules is done in Kibana's UI — that's where bulk actions and
  tag-based filtering live."

### Step 2: Show in Kibana

Navigate to **Security → Rules** → filter by **Elastic rules** tag.

"These are Elastic's vendor-maintained rules. Terraform installed them and
keeps them updated. The SOC team enables the ones relevant to their
environment directly in Kibana."

**Talking point:** "We don't manage 1,400+ prebuilt rules in `.tf` files.
Terraform owns the installation and updates. Kibana owns which ones are turned on.
That boundary is intentional."

---

## 8. Demo 7 — Fork a Prebuilt Rule, Import the Custom Copy into Git

> **Goal:** Show what happens when a detection engineer needs to customise a
> prebuilt rule beyond what exceptions can handle — and bring that fork under
> version control.

> ⚠️ **Kibana 8.17+ treats prebuilt rules as immutable.** You cannot directly
> edit the query or core fields of a vendor-maintained rule. The supported
> workflow is: **Duplicate → Edit the copy → Import into Terraform.**

### Step 1: Duplicate a prebuilt rule in Kibana

1. In **Security → Rules**, find a prebuilt rule (e.g., search for
   "GitHub Repository Deleted" or any prebuilt rule relevant to your org)
2. Click the rule name to open it
3. Click the **⋯ (actions menu)** → **Duplicate rule**
4. Kibana creates an editable copy named "**\[Rule Name\] \[Duplicate\]**"

### Step 2: Edit the duplicated rule

1. Open the duplicate rule → click **Edit rule settings**
2. All fields are now editable. Make a change:
   - **Definition tab:** Modify the query (e.g., add a `NOT` clause or
     narrow the index pattern)
   - **About tab:** Change severity, risk score, or add tags
3. Rename the rule to remove the `[Duplicate]` suffix — give it a clear name
   like `GitHub Repository Deleted — Custom`
4. Click **Save changes**

### Step 3: Explain the approach to the audience

"Prebuilt rules are maintained by Elastic — they get updated automatically,
and you can't edit them directly. When you need to customise one beyond what
exceptions can handle, you duplicate it. The copy is a fully custom rule that
you own. We bring it into Git like any other GUI-created rule."

### Step 4: Import the custom copy

```bash
# Find the duplicated rule
make list-rules
# → Look for the renamed rule, confirm it shows as "custom" not "prebuilt"

# Import it
make import-rule NAME="GitHub Repository Deleted"
```

The script generates a `.tf` file with both IDs in the header. Follow the
printed next-steps (same as Demo 3 — add to outputs.tf, `terraform init`,
`terraform import` with the `kibana_id`, `terraform plan`).

### Step 5: Review the generated .tf file

Open it — show it looks just like any custom rule. This is now tracked in Git
like everything else.

### Step 6: (Optional) Disable the original prebuilt rule

If the custom copy replaces the prebuilt original, disable the original in
Kibana to avoid duplicate alerts:

1. Go back to the original prebuilt rule
2. Toggle it off (or use bulk actions)

"Now we have one source of truth — the forked version in Git. The original
prebuilt rule stays installed but disabled, so Elastic updates still flow in
if we ever want to compare."

**Talking point:** "In practice, most teams leave prebuilt rules alone and use
exceptions for tuning. But when you do need to fork one — duplicate, edit,
import into Git. That's the path back to version control."

---

## 9. Demo 8 — Change a Query in Terraform and Redeploy

> **Goal:** Show editing an existing rule's query logic purely through code.

### Step 1: Edit an existing rule

Open `terraform/custom_rules/002_suspicious_powershell_encoded.tf`.

Change the query — for example, add a `NOT` clause to exclude a known-good
process:

**Before:**
```
process.name:"powershell.exe" AND process.command_line:(*-enc* OR *-EncodedCommand* OR *-e *)
```

**After:**
```
process.name:"powershell.exe" AND process.command_line:(*-enc* OR *-EncodedCommand* OR *-e *) AND NOT process.parent.name:"CcmExec.exe"
```

### Step 2: Test and plan

```bash
make test    # Still passes — structural tests don't care about query content
make plan
```

**Key moment:** The plan shows:
```
~ module.custom_rules.module.suspicious_powershell_encoded
    ~ query = "..." → "..."
```

"One line changed in the query. Terraform knows exactly what's different.
In a real workflow, this diff appears as a PR comment for peer review."

### Step 3: Deploy

```bash
make apply
```

Verify in Kibana — the rule's query has updated.

---

## 10. Demo 9 — Convert a Rule to a Building Block

> **Goal:** Show how to convert an existing rule into a building-block rule
> (one that feeds into other rules rather than generating alerts directly).

### Step 1: Edit the rule

Open `terraform/custom_rules/001_brute_force_login.tf`.

Add one line:

```hcl
  building_block_type = "default"
```

This goes anywhere inside the module block (e.g., after `risk_score`).

### Step 2: Plan and show the diff

```bash
make plan
```

The plan shows:
```
~ building_block_type = null → "default"
```

"That's it — one attribute. The rule becomes a building block. Its alerts
feed into higher-level correlation rules instead of showing up directly
in the alerts queue."

### Step 3: Deploy and verify

```bash
make apply
```

In Kibana, the rule should now show the building-block indicator.

### Step 4: Revert (optional — show rollback)

Remove the `building_block_type` line, run `make plan` and `make apply`.
Show it reverts cleanly.

"Version control means rollback is trivial — you just undo the change
and redeploy."

---

## 11. Demo 10 — The CI/CD Flow (PR → Plan → Merge → Apply)

> **Goal:** Show the full Git workflow that a detection engineer would follow
> day-to-day.

### Step 1: Create a branch

```bash
git checkout -b demo/new-rule
```

### Step 2: Make a change

Create a new rule or modify an existing one (any of the changes above work).

### Step 3: Test locally

```bash
make test
make plan
```

### Step 4: Commit and push

```bash
git add terraform/
git commit -m "feat: add suspicious scheduled task rule"
git push origin demo/new-rule
```

### Step 5: Open a PR (show in browser)

1. Go to the GitHub repo
2. Open a PR from `demo/new-rule` → `main`
3. **Show the CI running:** pytest tests, `terraform fmt`, `terraform validate`,
   `terraform plan`
4. **Show the plan output posted as a PR comment** — the reviewer sees exactly
   what will change in Elastic

### Step 6: Merge

Merge the PR.

"On merge to `main`, GitHub Actions runs `terraform apply` automatically.
The rule deploys to Elastic. No manual steps, no SSH, no clicking in Kibana."

**Talking point:** "This is the core value prop. The detection engineer writes
a rule, gets a peer review on the PR with the full plan output, merges, and
it's live. Rollback? Revert the PR."

---

## 12. Post-Demo Cleanup

**Between practice runs**, use the one-command reset:

```bash
make demo-reset
```

This automatically:
1. Reverts all file changes in `terraform/` back to the last commit
2. Removes untracked demo `.tf` files
3. Deletes `demo/*` git branches
4. Runs `terraform destroy` to clear Elastic
5. Deletes any GUI-created rules and leftover exception lists from Kibana
6. Redeploys the baseline rules and exceptions
7. Runs a quick health check

After it completes, the environment is identical to step 1 of this runbook.

**Manual cleanup** (if you prefer):

```bash
# If you want to reset to the pre-demo state:
git checkout main
git checkout HEAD -- terraform/
git clean -f terraform/custom_rules/ terraform/exceptions/
git branch -D demo/new-rule

# Redeploy clean state:
make destroy && make apply

# Or tear down everything:
make teardown
```

---

## Quick Reference — Key Commands

| What | Command |
|------|---------|
| Start the local stack | `make setup` |
| Health check | `make validate-lab` |
| Create a rule (wizard) | `make new-rule` |
| Create an exception (wizard) | `make new-exception` |
| List rules in Kibana | `make list-rules` |
| Import a GUI rule | `make import-rule NAME="rule name"` |
| Run unit tests | `make test` |
| Preview changes | `make plan` |
| Deploy | `make apply` |
| Full local CI | `make ci` |
| Show cheatsheet | `make cheatsheet` |

---

## Demo Talking Points Cheat Sheet

- **Why DaC?** "Manual rule management doesn't scale. When you have 50+ custom
  rules across environments, you need version control, peer review, and
  automated deployment."

- **Why Terraform?** "It's declarative — you describe what you want, not how to
  get there. The elasticstack provider handles the Kibana API calls. The plan
  shows you exactly what changes before anything deploys."

- **What about prebuilt rules?** "Terraform installs and updates them.
  Enablement stays in Kibana — it's better at bulk actions and tag-based
  filtering than Terraform would be."

- **What about exceptions?** "They're first-class resources, versioned and
  reviewed just like rules. Changing an exception never changes a rule."

- **What about the GUI?** "Detection engineers can still prototype in the GUI.
  The import workflow brings it back to Git. Once it's in Git, that's the
  source of truth."

- **Rollback?** "Revert the Git commit. Terraform apply. Done."

- **GitLab migration?** "The Terraform, modules, and tests are CI-agnostic.
  Only `.github/workflows/` needs to become `.gitlab-ci.yml`. The core
  framework ports directly."
