# GitLab Runners + AWS S3 — Operations Guide

This project's CI/CD pipeline ([.gitlab-ci.yml](../.gitlab-ci.yml)) is designed to run on
**dedicated, self-hosted GitLab Runners** with **AWS S3** for both:

1. **Terraform remote state** (S3 bucket + DynamoDB lock table)
2. **GitLab distributed cache** (`.terraform/` plugin cache, plan artifacts)

This document walks through provisioning both.

---

## 1. AWS resources

### 1a. S3 bucket for Terraform state

```bash
aws s3api create-bucket \
  --bucket company-tfstate-prod \
  --region us-east-1
aws s3api put-bucket-versioning \
  --bucket company-tfstate-prod \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --bucket company-tfstate-prod \
  --server-side-encryption-configuration '{
    "Rules": [{ "ApplyServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" } }]
  }'
aws s3api put-public-access-block \
  --bucket company-tfstate-prod \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 1b. DynamoDB table for state locking

```bash
aws dynamodb create-table \
  --table-name terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

### 1c. (Optional) S3 bucket for runner distributed cache

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

### 1d. IAM policy for the runner

Attach this policy to the runner's EC2 instance role (or an IAM user whose
credentials are stored as masked GitLab CI/CD variables):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TerraformState",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::company-tfstate-prod",
        "arn:aws:s3:::company-tfstate-prod/*"
      ]
    },
    {
      "Sid": "TerraformLocks",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:DescribeTable"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:*:table/terraform-locks"
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

If you can't use an instance role, use static credentials and switch to
`AuthenticationType = "access-key"` with `AccessKey` / `SecretKey` set
(or, preferably, mount them via a secrets manager).

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
| `AWS_ACCESS_KEY_ID` | `AKIA…` | ✅ | ✅ |
| `AWS_SECRET_ACCESS_KEY` | `…` | ✅ | ✅ |
| `AWS_DEFAULT_REGION` | `us-east-1` | ⬜ | ⬜ |
| `TF_STATE_BUCKET` | `company-tfstate-prod` | ⬜ | ✅ |
| `TF_STATE_KEY` | `elastic-dac/terraform.tfstate` | ⬜ | ✅ |
| `TF_STATE_LOCK_TABLE` | `terraform-locks` | ⬜ | ✅ |
| `RUNNER_TAG` | `elastic-dac-prod` | ⬜ | ⬜ |
| `ELASTICSEARCH_USERNAME` | `terraform` | ✅ | ✅ |
| `ELASTICSEARCH_PASSWORD` | `…` | ✅ | ✅ |
| `ELASTICSEARCH_ENDPOINTS` | `https://es.example.com:9243` | ⬜ | ✅ |
| `KIBANA_USERNAME` | `terraform` | ✅ | ✅ |
| `KIBANA_PASSWORD` | `…` | ✅ | ✅ |
| `KIBANA_ENDPOINT` | `https://kb.example.com:9243` | ⬜ | ✅ |
| `GITLAB_TOKEN` | project access token (`api`,`write_repository`) | ✅ | ✅ |
| `SYNC_UPSTREAM` | `true` *(set on the schedule, not project-wide)* | ⬜ | ⬜ |

If you use AWS instance-role auth on the runner, you can omit
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` here and rely solely on the
runner's IAM role.

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
