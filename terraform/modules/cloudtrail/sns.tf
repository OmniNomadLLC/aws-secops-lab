# CloudTrail meldt elke logbestand-levering op dit topic. Nu nog zonder
# subscribers; dag 2+ kan hier monitoring op aanhaken.
resource "aws_sns_topic" "trail" {
  name              = "${var.project_name}-cloudtrail-delivery"
  kms_master_key_id = aws_kms_key.cloudtrail.arn
}

data "aws_iam_policy_document" "trail_sns" {
  statement {
    sid       = "CloudTrailPublish"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.trail.arn]

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
}

resource "aws_sns_topic_policy" "trail" {
  arn    = aws_sns_topic.trail.arn
  policy = data.aws_iam_policy_document.trail_sns.json
}
