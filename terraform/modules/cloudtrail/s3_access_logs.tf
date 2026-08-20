# Access-logbucket: S3 server access logging van de trail-bucket komt hier
# terecht. Wie heeft wanneer welk logobject gelezen; de audit op de audit.
# Naar zichzelf loggen geeft een oneindige lus en een derde bucket lost niets
# op; hier eindigt de loggingketen bewust.
#tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_144: single-region lab; replicatie verdubbelt kosten zonder DR-eis
  bucket        = "${var.project_name}-s3-access-logs-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs]
}

# Met BucketOwnerEnforced bestaan ACL's niet meer, dus log delivery krijgt
# schrijfrecht via een bucket policy: alleen de S3-loggingservice, alleen
# vanuit ons eigen account, alleen met de trail-bucket als bron.
data "aws_iam_policy_document" "access_logs_bucket" {
  statement {
    sid       = "S3ServerAccessLogsDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.trail_logs.arn]
    }
  }
}

resource "aws_s3_bucket_notification" "access_logs" {
  bucket      = aws_s3_bucket.access_logs.id
  eventbridge = true
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

# De koppeling: trail-bucket logt zijn toegangen naar de access-logbucket.
resource "aws_s3_bucket_logging" "trail_logs" {
  bucket        = aws_s3_bucket.trail_logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "trail-bucket/"
}
