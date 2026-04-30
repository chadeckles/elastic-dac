# GitLab Runners + AWS S3 — Operations Guide

This project's CI/CD pipeline ([.gitlab-ci.yml](../.gitlab-ci.yml)) is designed to run on
**dedicated, self-hosted GitLab Runners** with **AWS S3** for both:

1. **Terraform remote state** (S3 bucket; native S3 state locking — no DynamoDB)
2. **GitLab distributed cache** (`.terraform/` plugin cache, plan artifacts)

Authentication uses the runner's **EC2 instance role**; no static AWS keys are
plumbed through GitLab variables.

This document walks through provisioning both.
---

## 1. AWS resources

### 1a. S3 bucket for Terraform state

> **Bucket name used in this guide:** `elastic-dac-terraform` — the bucket that
> backs this project's remote state. Substitute your own name if you've chosen
> something different, and keep it consistent across §1a, §1c, the GitLab
> `TF_STATE_BUCKET` variable, and `terraform/backend.tf.example`.

```bash
aws s3api create-bucket \
  --bucket elastic-dac-terraform \
  --region us-east-1
aws s3api put-bucket-versioning \
  --bucket elastic-dac-terraform \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --bucket elastic-dac-terraform \
  --server-side-encryption-configuration '{
    "Rules": [{ "ApplyServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" } }]
  }'
aws s3api put-public-access-block \
  --bucket elastic-dac-terraform \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

> **State locking:** Terraform 1.10+ supports native S3 state locking via S3
> conditional writes (`use_lockfile = true`). The lock is a tiny
> `<key>.tflock` object stored alongside your state file in the same bucket.
> No DynamoDB table is required — the IAM perms in §1b cover both state
> reads/writes and lock acquisition.

### 1b. (Optional) S3 bucket for runner distributed cache

If you operate more than one runner instance and want the `.terraform/` plugin
cache and pipeline artifacts to be reusable across runners, give them a
dedicated cache bucket:

```bash
aws s3api create-bucket \
  --bucket company-gitlab-runner-cache \
  --region us-east-1
aws s3api put-bucket-lifecycle-configuration \
  --bucket company-gitlab-runner-cache \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-cache",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "Expiration": { "Days": 14 }
    }]
  }'
```

### 1c. IAM policy for the runner

Attach this policy to the runner's EC2 instance role. With S3 native locking
the state and the lock object both live in the same bucket, so a single
bucket grant covers both. No DynamoDB statements required.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TerraformStateAndLock",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::elastic-dac-terraform",
        "arn:aws:s3:::elastic-dac-terraform/*"
      ]
    },
    {
      "Sid": "RunnerCache",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::company-gitlab-runner-cache",
        "arn:aws:s3:::company-gitlab-runner-cache/*"
      ]
    }
  ]
}
```

> The `s3:PutObject` + `s3:DeleteObject` on the state bucket are also what
> Terraform uses to create and release the `<key>.tflock` lock object during
> `plan` / `apply`. If you ever need to break a stale lock manually:
> `aws s3 rm s3://elastic-dac-terraform/elastic-dac/terraform.tfstate.tflock`.

---

## 2. Register a dedicated GitLab Runner

Pin the project's CI jobs to **dedicated** runners (not the shared SaaS pool)
so credentials never leave your network.

### 2a. Install the runner

On a hardened EC2 instance / VM in the appropriate VPC:

```bash
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install -y gitlab-runner
```

### 2b. Register against the project

In GitLab: **Settings → CI/CD → Runners → New project runner**.
Copy the registration token, then:

```bash
sudo gitlab-runner register \
  --non-interactive \
  --url "https://gitlab.com/" \
  --registration-token "<token>" \
  --executor "docker" \
  --docker-image "alpine:3.20" \
  --description "elastic-dac dedicated runner" \
  --tag-list "elastic-dac,elastic-dac-prod" \
  --run-untagged="false" \
  --locked="true" \
  --access-level="ref_protected"
```

> **Why `--run-untagged=false` and `--locked=true`?**
> Together they guarantee this runner only services jobs that:
> 1. Live in this project (or its allow-list), and
> 2. Carry the matching `tags:` block.
>
> The pipeline's `default.tags` of `$RUNNER_TAG` (default `elastic-dac`) is what
> selects this runner. Set `RUNNER_TAG` per-environment if you want different
> runners for staging vs. prod.

### 2c. Configure the S3-backed cache

Edit `/etc/gitlab-runner/config.toml`:

```toml
concurrent = 4
check_interval = 0

[[runners]]
  name = "elastic-dac dedicated runner"
  url = "https://gitlab.com/"
  token = "..."   # set by `register`
  executor = "docker"

  [runners.docker]
    image = "alpine:3.20"
    privileged = false
    disable_cache = false
    volumes = ["/cache"]

  [runners.cache]
    Type = "s3"
    Shared = true
    [runners.cache.s3]
      ServerAddress      = "s3.amazonaws.com"
      BucketName         = "company-gitlab-runner-cache"
      BucketLocation     = "us-east-1"
      AuthenticationType = "iam"   # uses the EC2 instance role
```

Using `AuthenticationType = "iam"` keeps everything off static keys — the
same instance role that grants the runner access to the Terraform state
bucket also covers the cache bucket (see the IAM policy in §1c).

Then:

```bash
sudo systemctl restart gitlab-runner
```

---

## 3. GitLab project CI/CD variables

**Settings → CI/CD → Variables.** Mark every credential **Masked** and
**Protected** (so they're only available on protected branches/tags).

| Variable | Example | Masked | Protected |
|---|---|---|---|
| `AWS_DEFAULT_REGION` | `us-east-1` | ⬜ | ✅ |
| `TF_STATE_BUCKET` | `elastic-dac-terraform` | ⬜ | ✅ |
| `TF_STATE_KEY` | `elastic-dac/terraform.tfstate` | ⬜ | ✅ |
| `RUNNER_TAG` | `elastic-dac-prod` | ⬜ | ⬜ |
| `KIBANA_API_KEY` | `VnVhQ2ZH…` *(the `encoded` field from POST /_security/api_key)* | ✅ | ✅ |
| `KIBANA_ENDPOINT` | `https://<deployment>.kb.<region>.aws.elastic-cloud.com:9243` | ⬜ | ✅ |
| `GITLAB_TOKEN` | project access token (`api`,`write_repository`) | ✅ | ✅ |
| `SYNC_UPSTREAM` | `true` *(set on the schedule, not project-wide)* | ⬜ | ⬜ |

> **No AWS keys in GitLab.** AWS credentials come from the runner's EC2
> instance role via IMDS — don't add `AWS_ACCESS_KEY_ID` or
> `AWS_SECRET_ACCESS_KEY` to this project. If you ever need to run the
> pipeline somewhere without an instance role (e.g. a non-AWS runner), add
> them then — but for the supported topology they are not used.

---

## 4. Activate the S3 backend in Terraform

The state backend lives in [terraform/backend.tf.example](../terraform/backend.tf.example).
Copy it into place and the pipeline will pick it up:

```bash
cp terraform/backend.tf.example terraform/backend.tf
git add terraform/backend.tf
git commit -m "chore: enable S3 remote state"
```

Backend values come from `-backend-config` flags in the pipeline (see the
`.terraform-init` snippet in [.gitlab-ci.yml](../.gitlab-ci.yml)) — you do **not**
need to hard-code the bucket name in `backend.tf`.

---

## 5. Schedule the upstream sync pipeline

**Settings → CI/CD → Schedules → New schedule**:

- **Description:** Weekly upstream rule sync
- **Interval pattern:** `0 8 * * 1` (Mondays 08:00 UTC)
- **Target branch:** `main`
- **Variables:** add `SYNC_UPSTREAM` = `true`

Only the `sync:upstream-rules` job (in
[.gitlab/ci/sync-upstream.gitlab-ci.yml](ci/sync-upstream.gitlab-ci.yml))
will activate; the regular plan/apply jobs will be skipped because of their
`rules:` clauses.
