"""
scripts.importers — Brownfield bulk-import helpers for Elastic DaC.

Each submodule fetches one resource family from Kibana and renders the
corresponding `.tf` files + Terraform 1.5 `import {}` blocks for adoption
into the repo. See IMPLEMENTATION_STRATEGY.md for the rollout phases that
consume these modules.
"""
