# De uitvoeringsrol van de Lambda. Zelfde lat als dag 1: exacte acties op
# exacte resources, en waar dat niet kan staat de reden als comment erbij.

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    # Alleen Lambda's uit dít account mogen de rol aannemen (confused deputy).
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "lambda_permissions" {
  # Loggen mag alleen in de eigen loggroep. logs:CreateLogGroup ontbreekt
  # bewust: de loggroep bestaat al (Terraform maakt hem), dus de Lambda
  # hoeft er geen te kunnen aanmaken.
  statement {
    sid = "WriteOwnLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    # Log-streamnamen bevatten een runtime-gegenereerd instance-ID; de
    # wildcard geldt alleen bínnen onze eigen loggroep (zelfde motivatie
    # als de log-stream-wildcard bij cloudtrail).
    #tfsec:ignore:aws-iam-no-policy-wildcards -- wildcard alleen op de streamnaam bínnen de eigen loggroep; streamnamen bevatten een runtime instance-ID
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  # De verrijking (enrich.py): actuele publieke status van een bucket opvragen.
  statement {
    sid = "ReadBucketPublicState"
    actions = [
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
    ]
    # Alle buckets, en dat is hier de juiste scope: de detectie moet júist
    # kunnen kijken naar buckets die we vooraf niet kennen (ook LET-restanten).
    # Beide acties zijn read-only metadata; objectdata kan hiermee niet gelezen worden.
    #tfsec:ignore:aws-iam-no-policy-wildcards -- detectie moet elke (ook onbekende) bucket kunnen beoordelen; beide acties zijn read-only metadata
    resources = ["arn:aws:s3:::*"]
  }

  # Env vars (ALERT_ENDPOINT) zijn versleuteld met de lab-CMK; de rol mag
  # alleen ontsleutelen, en alleen met precies die key.
  statement {
    sid       = "DecryptEnvVars"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }

  # Mislukte events naar de eigen DLQ kunnen schrijven, nergens anders heen.
  statement {
    sid       = "SendToOwnDlq"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  # X-Ray-tracing (tracing_config Active). Deze acties ondersteunen geen
  # resource-scoping: traces zijn geen adresseerbare resource, dus "*" is
  # hier het minimum dat werkt, niet een gemakzuchtige wildcard.
  statement {
    sid = "XRayTracing"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.function_name}-permissions"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}
