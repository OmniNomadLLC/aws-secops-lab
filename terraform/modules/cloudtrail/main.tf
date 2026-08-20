data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # De trail-ARN vooraf construeren in plaats van aws_cloudtrail.main.arn gebruiken,
  # anders ontstaat een cirkel: de bucket policy heeft de ARN nodig, de trail heeft
  # de bucket policy nodig.
  trail_name = "${var.project_name}-trail"
  trail_arn  = "arn:aws:cloudtrail:${data.aws_region.current.name}:${local.account_id}:trail/${local.trail_name}"
}

# ---------------------------------------------------------------------------
# S3-bucket voor de trail-logs
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail_logs" {
  bucket = "${var.project_name}-cloudtrail-${local.account_id}"

  # Lab: aan het eind van de week gaat alles door terraform destroy, ook als er
  # nog logobjecten in staan. In productie zou dit false zijn.
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  rule {
    id     = "expire-trail-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail_logs]
}

# CloudTrail mag alleen als service, alleen naar het eigen accountpad, en alleen
# namens onze eigen trail (SourceArn) schrijven. Zonder die conditie kan elke
# willekeurige trail in dit bucket schrijven: confused deputy.
data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail_logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = data.aws_iam_policy_document.trail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.trail_logs]
}

# ---------------------------------------------------------------------------
# CloudWatch-loggroep + least-privilege rol voor CloudTrail
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "trail_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    # Alleen onze eigen trail mag deze rol aannemen, niet elke CloudTrail in
    # elk account.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

# Precies twee acties, precies één loggroep. Dit is de least-privilege-lat
# waar elke volgende rol in dit project ook overheen moet.
data "aws_iam_policy_document" "trail_to_logs" {
  statement {
    sid = "WriteToTrailLogGroup"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role" "trail_to_logs" {
  name               = "${var.project_name}-cloudtrail-to-cw-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name   = "write-cloudtrail-log-group"
  role   = aws_iam_role.trail_to_logs.id
  policy = data.aws_iam_policy_document.trail_to_logs.json
}

# ---------------------------------------------------------------------------
# De trail zelf
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail_logs.id

  # Multi-region: ook API-calls buiten eu-west-1 (zoals IAM in us-east-1) worden
  # gelogd. De eerste trail met management-events is gratis, ook multi-region.
  is_multi_region_trail         = true
  include_global_service_events = true

  # Digest-bestanden waarmee aantoonbaar is dat logs niet zijn aangepast.
  enable_log_file_validation = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_logs.arn

  depends_on = [aws_s3_bucket_policy.trail_logs]
}
