# =============================================================================
# Approved Cron Jobs — Exception List
# =============================================================================
# Suppresses cron-persistence false positives for known non-root users
# that are expected to create scheduled jobs.
# =============================================================================

module "approved_cron" {
  source = "../modules/exception_list"

  list_id     = "approved-cron-jobs"
  name        = "Approved Cron Jobs"
  description = "Non-root users allowed to create cron entries."
  type        = "detection"
  tags        = ["linux", "cron", "approved"]

  items = [
    {
      item_id     = "deploy-user"
      name        = "Deploy User Cron"
      description = "The deploy user creates cron jobs for scheduled deployments."
      tags        = ["deploy"]
      entries = [
        {
          field    = "user.name"
          type     = "match"
          operator = "included"
          value    = "deploy"
        }
      ]
    },
  ]

  space_id = var.space_id
}
