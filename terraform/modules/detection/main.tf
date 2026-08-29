data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  function_name = "${var.project_name}-detection"
}

# ---------------------------------------------------------------------------
# Het zip-pakket: alleen src/, geen tests of tooling
# ---------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/.build/${local.function_name}.zip"

  excludes = [
    "tests",
    "conftest.py",
    "requirements.txt", # alleen test-dependencies; de Lambda zelf gebruikt puur stdlib + boto3 (zit in de runtime)
    "__pycache__",
    "src/__pycache__",
    ".pytest_cache",
  ]
}

# ---------------------------------------------------------------------------
# Loggroep vooraf aanmaken: dan heeft de rol logs:CreateLogGroup niet nodig
# en bepalen wij retentie en encryptie in plaats van de Lambda-service.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# ---------------------------------------------------------------------------
# Dead-letter queue: events waarop de Lambda twee retries lang faalt komen
# hier terecht in plaats van stil te verdwijnen. SSE-SQS is gratis en volstaat
# voor de scanners; er staan alleen al-versleutelde CloudTrail-kopieën in.
# ---------------------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.function_name}-dlq"
  message_retention_seconds = 1209600 # 14 dagen, het maximum: tijd genoeg om te onderzoeken
  sqs_managed_sse_enabled   = true
}

# ---------------------------------------------------------------------------
# De Lambda zelf
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "detection" {
  # checkov:skip=CKV_AWS_115: reserved concurrency is op dit account onmogelijk: de accountquota is 10 concurrent executions totaal en AWS eist minimaal 10 ongereserveerd (10-1 < 10, PutFunctionConcurrency weigert elke waarde). De quota van 10 begrenst de blast radius feitelijk al strakker dan een reservering zou doen.
  # checkov:skip=CKV_AWS_117: er is geen VPC in dit lab; de Lambda praat alleen met publieke AWS-API's, een VPC + endpoints zou puur kosten toevoegen
  # checkov:skip=CKV_AWS_272: code signing vereist een Signer-profiel + signing jobs in de pipeline; buiten scope voor het lab, de integriteit wordt geborgd door CI op de bron
  function_name = local.function_name
  description   = "Evalueert CloudTrail-events tegen securityregels en alarmeert."

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  handler          = "src.handler.handler"
  runtime          = "python3.12" # zelfde versie als de CI-testjob
  architectures    = ["arm64"]    # goedkoper per ms en ruim snel genoeg
  memory_size      = 128
  timeout          = 10 # event evalueren + 2 S3-reads + 1 HTTPS-post; ruim, maar begrensd

  role = aws_iam_role.lambda.arn

  kms_key_arn = var.kms_key_arn # versleutelt de env vars met onze CMK i.p.v. de default

  environment {
    variables = {
      ALERT_ENDPOINT = var.alert_endpoint
      ALERT_FORMAT   = var.alert_format
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active" # X-Ray; free tier dekt 100k traces/maand, dit lab haalt daar geen fractie van
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

# ---------------------------------------------------------------------------
# EventBridge: het grove filter. Alleen calls waar een regel iets mee kan
# bereiken de Lambda; de rest wordt bij AWS al weggefilterd en kost ons dus
# geen invocaties. Eén map met patronen, for_each maakt er rules van:
# een regel toevoegen = een entry toevoegen.
#
# Globale events (console-sign-ins, IAM-calls) landen op de EventBridge-bus
# in us-east-1; global_events.tf forwardt ze naar de default bus hier, waar
# de root-activity-rule ze oppikt. De beperking van dag 3 is daarmee gedicht.
# ---------------------------------------------------------------------------

locals {
  event_rules = {
    "s3-public" = {
      description = "CloudTrail S3-calls die een bucket publiek kunnen maken."
      pattern = {
        source      = ["aws.s3"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          # CloudTrail gebruikt de "Bucket"-variant van de public-access-block-
          # namen (≠ de S3-API-naam); de kale variant blijft als alias staan.
          eventName = [
            "PutBucketAcl",
            "PutBucketPolicy",
            "DeleteBucketPublicAccessBlock",
            "DeletePublicAccessBlock",
            "PutBucketPublicAccessBlock",
            "PutPublicAccessBlock",
          ]
        }
      }
    }
    "root-activity" = {
      description = "Elke actie van het root-account, incl. geforwarde globale events uit us-east-1."
      pattern = {
        detail-type = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
        detail = {
          userIdentity = { type = ["Root"] }
        }
      }
    }
    "sg-world-open" = {
      description = "Security-group-regels die naar het internet opengezet worden."
      pattern = {
        source      = ["aws.ec2"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress"]
        }
      }
    }
    "trail-tamper" = {
      description = "CloudTrail-logging die gestopt, verwijderd of aangepast wordt."
      pattern = {
        source      = ["aws.cloudtrail"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventName = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
        }
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "detection" {
  for_each = local.event_rules

  name          = "${var.project_name}-${each.key}-events"
  description   = each.value.description
  event_pattern = jsonencode(each.value.pattern)
}

resource "aws_cloudwatch_event_target" "detection" {
  for_each = local.event_rules

  rule = aws_cloudwatch_event_rule.detection[each.key].name
  arn  = aws_lambda_function.detection.arn
}

# EventBridge mag deze functie aanroepen, maar alleen vanuit precies deze rules.
resource "aws_lambda_permission" "detection" {
  for_each = local.event_rules

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection[each.key].arn
}

# De bestaande s3-rule verhuist alleen van adres binnen de state; zonder deze
# moved-blocks zou Terraform hem afbreken en opnieuw aanmaken.
moved {
  from = aws_cloudwatch_event_rule.s3_public
  to   = aws_cloudwatch_event_rule.detection["s3-public"]
}

moved {
  from = aws_cloudwatch_event_target.lambda
  to   = aws_cloudwatch_event_target.detection["s3-public"]
}

moved {
  from = aws_lambda_permission.eventbridge
  to   = aws_lambda_permission.detection["s3-public"]
}

# ---------------------------------------------------------------------------
# De dagelijkse audit (IAM-KEY-005): een schedule is geen CloudTrail-event,
# dus een eigen rule. De handler herkent detail-type "Scheduled Event".
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "daily_audit" {
  name                = "${var.project_name}-daily-audit"
  description         = "Dagelijkse toestandsaudit (o.a. verouderde IAM-keys)."
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "daily_audit" {
  rule = aws_cloudwatch_event_rule.daily_audit.name
  arn  = aws_lambda_function.detection.arn
}

resource "aws_lambda_permission" "daily_audit" {
  statement_id  = "AllowEventBridge-daily-audit"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_audit.arn
}
