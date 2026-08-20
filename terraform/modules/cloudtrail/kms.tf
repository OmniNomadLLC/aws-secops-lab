# Eén CMK voor de hele cloudtrail-module: trail, S3-buckets, loggroep en SNS.
# Kost $1/maand (pro rata). De key policy werkt als een tweede slot naast IAM:
# elke service krijgt alleen het werkwoord dat hij nodig heeft, vergrendeld op
# de resource waarvoor hij het nodig heeft.
data "aws_iam_policy_document" "cmk" {
  # checkov:skip=CKV_AWS_109: dit is een KMS-key-policy, geen identity-policy; Resource "*" betekent hier "deze key zelf" en het root-statement is door AWS vereist om de key beheerbaar te houden
  # checkov:skip=CKV_AWS_111: zie CKV_AWS_109
  # checkov:skip=CKV_AWS_356: zie CKV_AWS_109
  # Zonder dit statement is de key onbeheerbaar: niemand kan hem dan nog
  # aanpassen of verwijderen, ook wij niet. Dit delegeert keybeheer aan IAM
  # binnen het eigen account; het is de standaard-bodem onder elke key policy.
  statement {
    sid       = "EnableIAMDelegation"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid = "CloudTrailEncrypt"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt", # nodig voor publiceren naar het versleutelde SNS-topic
      "kms:DescribeKey",
    ]
    resources = ["*"]

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
    sid = "CloudWatchLogsEncrypt"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:log-group:/aws/cloudtrail/${var.project_name}"]
    }
  }

  # S3 server access logging schrijft versleuteld naar de access-logbucket.
  statement {
    sid = "S3LogDeliveryEncrypt"
    actions = [
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "${var.project_name}: CMK voor CloudTrail, logbuckets, loggroep en SNS"
  enable_key_rotation     = true
  deletion_window_in_days = 7 # minimum; lab wordt aan het eind vernietigd
  policy                  = data.aws_iam_policy_document.cmk.json
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.project_name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}
