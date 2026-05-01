# Implementation Strategy — Brownfield Migration to Detection as Code

> **Status:** Living document. Update as we learn from each phase.
> **Scope:** How we move an existing, "heavy" Elastic Security configuration —
> live custom detection rules, shared exception lists, and rule-scoped
> exception items — into the Terraform-managed [Detection as Code](README.md)
> framework in this repo **without disrupting active SOC operations**.
>
> **Out of scope (for now):** the `endpoint_list` and endpoint trusted-apps.
> Those are owned by the Endpoint/EDR side and are explicitly excluded from
> the bulk importer. Add them later as a separate workstream if needed.
>
> **Owners:**
> - Detection Engineering — generator correctness, MR triage, rule reviews
> - SecOps / Detection Ops — drift adjudication, cutover go/no-go
> - Platform / SRE — CI runners, S3 backend, IAM for the GitLab pipeline

---

## Table of Contents

- [Goals & Non-Goals](#goals--non-goals)
- [What We Import (and What We Don't)](#what-we-import-and-what-we-dont)
- [Why `terraform import` Alone Isn't Enough](#why-terraform-import-alone-isnt-enough)
- [Phased Rollout](#phased-rollout)
  - [Phase 0 — Snapshot & Soft Freeze](#phase-0--snapshot--soft-freeze)
  - [Phase 1 — Codify in a Parallel Space](#phase-1--codify-in-a-parallel-space)
  - [Phase 2 — Shadow / Parallel Run](#phase-2--shadow--parallel-run)
  - [Phase 3 — Cutover](#phase-3--cutover)
  - [Phase 4 — Steady State + Drift Loop](#phase-4--steady-state--drift-loop)
- [The Drift Reconciliation Loop](#the-drift-reconciliation-loop)
- [Risk Register](#risk-register)
- [Rollback Plan](#rollback-plan)
- [Decisions Log](#decisions-log)
- [Open Questions](#open-questions)

---

## Goals & Non-Goals

### Goals

1. **Capture the current operational config as code**, faithfully and
   reproducibly, with no behavior change at cutover.
2. **Run code and UI side-by-side** for a defined parallel period so
   leadership can make an informed go/no-go.
3. **Provide a sustainable path** for analysts who continue to use the Kibana
   UI to create or tune rules — those changes flow back into the repo via
   reviewable MRs, not by accident.
4. **Keep the cutover boring.** The first `terraform apply` after the flip
   should be a no-op.

### Non-Goals

- Re-architecting rule taxonomy, naming, or tag conventions during migration.
  (Do that *after* you have green plans on `main`. One change at a time.)
- Migrating Endpoint/EDR `endpoint_list` items.
- Replacing the existing GUI workflow for Kibana-side dashboards, timelines,
  or alert triage.

---

## What We Import (and What We Don't)

| Resource | Scope | Source API | Target folder | Notes |
|---|---|---|---|---|
| Custom detection rules (non-immutable) | ✅ in scope | `GET /api/detection_engine/rules/_find` | [terraform/custom_rules/](terraform/custom_rules/) | One `.tf` per rule, mirroring the [detection_rule](terraform/modules/detection_rule/) module interface |
| Prebuilt rules (immutable) | ❌ out | n/a | [terraform/prebuilt_rules.tf](terraform/prebuilt_rules.tf) | Already managed declaratively — install/update only, enablement stays in Kibana |
| Shared exception lists (multi-rule) | ✅ in scope | `GET /api/exception_lists/_find` + `/items/_find` | [terraform/exceptions/](terraform/exceptions/) | One `.tf` per list with all items inline |
| Rule-scoped exception items (rule-default lists) | ✅ in scope | `GET /api/detection_engine/rules/{id}/exceptions` (or `/api/exception_lists/items/_find` filtered by the rule's default list) | [terraform/rule_exceptions/](terraform/rule_exceptions/) | One `.tf` per rule whose default list has items |
| Endpoint exception list (`endpoint_list`) | ❌ out | `findEndpointListItems` / `readEndpointListItem` | n/a | Excluded by request — separate workstream if needed later |
| Value lists (`/api/lists/index`) | ❌ out (initial) | `GET /api/lists/_find` | n/a | Add later only if a generator dump shows entries reference value-list IDs we can't resolve |
| Dashboards, timelines, cases, alert tuning | ❌ out | n/a | n/a | UI-native, not infra |

---

## Why `terraform import` Alone Isn't Enough

| Concern | Reality |
|---|---|
| Generates HCL? | No — only writes state. |
| Terraform 1.5+ `import {}` block + `-generate-config-out`? | Generates partial HCL but is **lossy for nested attributes** like rule `threat[]`, exception `entries`, and the `mitre_attack` simplified shape this repo uses. We'd ship cleanup work to humans for every resource. |
| Bulk-friendly? | One CLI invocation per resource. Tolerable for 5 rules, untenable for the current footprint. |
| Knows the right module address? | No — the `.tf` must already exist. So we'd need a generator anyway. |

**Decision:** build a generator (`scripts/bulk_import.py`) that emits **both**
the canonical `.tf` and the matching `import` blocks. It dumps the API to a
local cache so we can iterate on the generator without re-hitting prod.

---

## Phased Rollout

### Phase 0 — Snapshot & Soft Freeze

**Duration:** ~1 day. **Owner:** Detection Engineering + Detection Ops.

1. Run `make bulk-import-dump` against prod to write raw API JSON under
   `./.import-cache/<YYYY-MM-DD>/`. Commit the cache directory tag (the
   directory itself stays gitignored — we tag the date in the migration MR).
2. Tag a Kibana saved-objects export of detection rules + exception lists as
   the **immutable rollback snapshot** and stash it in object storage.
3. Announce a **soft freeze on shared exception lists** in `#detections`.
   Rule authoring can continue (we'll handle that drift in Phase 2). Endpoint
   trusted-apps are unaffected.

**Exit criteria:**
- `./.import-cache/<date>/rules/`, `/exception_lists/`, `/rule_exceptions/`
  populated and parseable by the generator.
- Snapshot saved-objects export uploaded with a known URI documented in the
  migration MR description.

---

### Phase 1 — Codify in a Parallel Space

**Duration:** 1–2 days, mostly automated. **Owner:** Detection Engineering.

1. Provision (or reuse) a non-prod Kibana **space** that mirrors prod
   policy/index access. Call it `dac-shadow`.
2. Run `make bulk-import` to:
   - Render `.tf` files into `terraform/custom_rules/`,
     `terraform/exceptions/`, and `terraform/rule_exceptions/`.
   - Append entries to a single, generated [terraform/imports.tf](terraform/)
     using Terraform 1.5+ `import {}` blocks.
   - Update each folder's `outputs.tf` to register the new modules.
3. `terraform init && terraform plan -var kibana_space_id=dac-shadow`
   — first plan typically shows the imports landing as no-ops on `apply`.
4. `terraform apply` to hydrate state. **Resulting plan must be empty.**
   Anything non-empty means generator drift; fix the generator (not the
   resource), regenerate, repeat. This is the cheap loop.

**Exit criteria:**
- `terraform plan` is empty against `dac-shadow`.
- All [tests/test_rules.py](tests/test_rules.py) tests pass on the generated tree.
- The migration MR is open, reviewable, and the diff makes sense to a human.

---

### Phase 2 — Shadow / Parallel Run

**Duration:** 2–3 weeks (negotiate with leadership). **Owner:** Detection Ops.

1. Re-target Terraform at the **real prod space**. Wire CI to run
   `terraform plan` only — **no apply** — on every MR and on a nightly
   schedule. Surface plan output as an MR comment / pipeline artifact.
   Enforce plan-only by keeping the GitLab CI variable
   **`TF_AUTO_APPLY="false"`** (the default). With the gate off, the
   `terraform:apply` job is not created at all — there is no button to
   click, no race condition, no "oops."
2. Treat every non-empty nightly plan as a triage item:
   - **UI-authored new rule** → run the importer in single-resource mode,
     open an MR titled `drift: adopt <name> from Kibana UI`, route to
     Detection Engineering for review.
   - **UI-authored modification of a tracked resource** → open an MR with
     the diff and a "revert vs. adopt" checklist; require explicit decision.
   - **UI-side deletion** → open an MR proposing the same deletion in code,
     require explicit approval (don't ever silently delete).
3. Track triage volume and false-positive rate of the generator. If
   generator bugs are still appearing late in week 2, **extend** the
   parallel period — do not cut over.

**Exit criteria (all must hold for ≥5 consecutive business days):**
- Nightly `plan` exits cleanly (`-detailed-exitcode = 0`).
- All UI-induced drift has been adopted, reverted, or explicitly accepted.
- Detection Ops + Detection Engineering both sign off in the cutover ticket.

---

### Phase 3 — Cutover

**Duration:** one MR, one CI run. **Owner:** Detection Ops + Platform.

1. Open the **cutover MR** that flips CI from `plan-only` to
   `plan + manual-approval apply` on `main`. Mechanically this is a
   single change: set the GitLab CI variable
   **`TF_AUTO_APPLY="true"`** (Settings → CI/CD → Variables, Protected,
   Masked not required). The pipeline scaffolding already exists per the
   [README](README.md#cicd-pipeline); the gate just stops hiding the job.
2. Merge during a quiet window. The first `apply` must be a no-op. If it
   isn't, **abort and revert the MR** — Phase 2 wasn't done.
3. Update `#detections` channel topic and the on-call runbook to point at
   the new "edits go through MR" workflow. Keep the GUI escape hatch open
   (covered by the drift loop).

**Exit criteria:**
- First post-cutover `apply` reports zero changes.
- Runbook updated, on-call briefed, GUI-edit policy documented.

---

### Phase 4 — Steady State + Drift Loop

**Duration:** ongoing. **Owner:** Detection Engineering (rotating).

This is the answer to *"users will still use the UI sometimes."* The drift
loop is not a one-time tool; it's a **recurring CI job**. See the next
section for mechanics.

**Health metrics to track (monthly):**
- Mean time from UI authoring → MR adoption.
- Number of nightly drifts adjudicated (adopt / revert / accept).
- Number of times an `apply` reverted a UI change (should trend toward zero
  as authors learn the MR path).
- Generator regression count.

---

## The Drift Reconciliation Loop

Triggered nightly by GitLab Schedules **and** on-demand via
`make drift-check`. Mechanically:

1. `terraform plan -detailed-exitcode -out=drift.plan`. Exit `0` → done.
2. `terraform show -json drift.plan` → JSON.
3. A small Python helper (`scripts/drift_triage.py`, planned) classifies each
   `resource_change`:
   - `create` not in code → **new in Kibana**, run bulk importer in
     single-resource mode against that resource and open an MR.
   - `update` of a tracked resource → open an MR carrying the proposed diff
     plus a `revert | adopt` checkbox in the description.
   - `delete` of a tracked resource → open an MR proposing the same delete,
     mark it `needs:explicit-approval`.
4. Post a single Slack/Teams summary with counts and MR links.

The same generator powers Phase 1 (bulk) and Phase 4 (single-resource).
Different mode, identical templates. That's deliberate — one source of
truth for "what does this rule look like in HCL?"

---

## Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Generator silently drops a field (e.g. obscure rule type) | Med | High | `terraform plan` post-import must be empty; loud unknown-key warning in generator |
| 2 | `rule_id` vs Kibana internal `id` confusion in `import` blocks | High | High | Generator emits both; import addresses use internal `id`; covered by the comment block in each generated file |
| 3 | Exception `entries` referencing value-list IDs we don't track | Med | Med | Generator dumps the raw entry; flags resources containing `list`-type entries for human review before MR |
| 4 | Rule-default lists named with non-deterministic IDs in old envs | Med | Med | Generator pulls the list_id from each rule's `exceptions_list[]`, doesn't guess from name |
| 5 | UI changes during Phase 1 cause Phase 2 noise | High | Low | Soft freeze + nightly drift MRs explicitly route them; this is *expected*, not a failure |
| 6 | First `apply` post-cutover isn't a no-op | Low | Critical | Abort/revert protocol; Phase 2 exit criteria explicitly gate on this |
| 7 | Pytest tag rules (e.g. `Team:` prefix) reject imported rules | High | Low | Generator stamps `Team: Imported` on rules missing the tag; flag for retag in MR |
| 8 | Drift MR volume overwhelms reviewers | Med | Med | Coalesce by author/day; tune nightly window; if persistent, tighten UI-edit policy |

---

## Rollback Plan

1. **Pre-cutover (Phase 0–2):** revert the migration MR. State doesn't yet
   manage prod; nothing to undo. Restore from saved-objects snapshot only if
   Phase 1 was accidentally pointed at prod (it shouldn't be).
2. **At cutover (Phase 3):** if the first `apply` shows changes, revert the
   pipeline-flip MR. State is hydrated but read-only; investigate the diff,
   regenerate, retry.
3. **Post-cutover (Phase 4):** standard Terraform — `git revert` the
   offending MR, CI applies the revert. The saved-objects snapshot from
   Phase 0 remains the catastrophic fallback for ~90 days.

---

## Decisions Log

> Append-only. Date + decision + rationale.

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-01 | Build a generator that emits HCL **and** Terraform 1.5+ `import {}` blocks, instead of relying on `terraform plan -generate-config-out`. | The auto-generator is lossy for nested attributes (`threat`, `entries`); we'd hand-edit every resource anyway. Custom generator amortizes that. |
| 2026-05-01 | Exclude `endpoint_list` from the bulk importer for the initial rollout. | Owned by Endpoint/EDR; not on the critical path; reduces blast radius. |
| 2026-05-01 | Phased rollout (0 → 4) with a hard exit criterion at Phase 2 of "5 consecutive empty nightly plans". | Forces an objective go/no-go signal instead of a calendar deadline. |

---

## Open Questions

- Which non-prod space will host Phase 1 (`dac-shadow`)? Who provisions it?
- Are there value lists (`/api/lists`) currently referenced by exception
  entries? If yes, do we adopt them in this migration or treat as a Phase-5
  follow-on?
- What's the MR-review SLA for nightly drift items? (Detection Eng to
  propose; SecOps to ratify.)
- For the Slack/Teams summary in the drift loop, which channel and which
  bot identity?

---

_Last updated: 2026-05-01 by Detection Engineering. Update this date and
the Decisions Log whenever assumptions change._
