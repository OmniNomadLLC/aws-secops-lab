# ---------------------------------------------------------------------------
# Cross-region forwarding van globale root-events uit us-east-1.
#
# Waarom us-east-1: globale CloudTrail-events (console-sign-ins op root,
# IAM-calls) landen altijd op de EventBridge default bus in us-east-1, nooit
# in de thuisregio. De regels in main.tf zien die events dus per definitie
# niet; dit bestand dicht dat gat.
#
# Waarom forwarden in plaats van een tweede Lambda in us-east-1: de hele
# detectieketen (Lambda, DLQ, CMK, alerting) staat al in de thuisregio en
# dupliceren zou twee codepaden en dubbele IAM opleveren. EventBridge kan
# een event 1-op-1 naar een bus in een andere regio sturen; het detail blijft
# daarbij intact, dus de bestaande "root-activity"-rule op de default bus in
# de thuisregio matcht het geforwarde event gewoon en de Lambda krijgt het
# via het normale pad binnen.
#
# Keten: root-event in us-east-1 -> rule global_root -> PutEvents (via de
# forward-rol) naar de default bus in de thuisregio -> rule "root-activity"
# -> Lambda -> alert.
# ---------------------------------------------------------------------------

# De configuration_aliases-declaratie voor aws.us_east_1 staat in versions.tf:
# een module mag maar een required_providers-blok hebben en daar staat archive al.

locals {
  # De default bus in de thuisregio; daar luistert de bestaande
  # root-activity-rule al op.
  home_default_bus_arn = "arn:aws:events:${data.aws_region.current.name}:${local.account_id}:event-bus/default"
}

resource "aws_cloudwatch_event_rule" "global_root" {
  provider = aws.us_east_1

  name        = "${var.project_name}-global-root-events"
  description = "Globale root-events (console-sign-in en IAM-calls) die alleen in us-east-1 landen."
  event_pattern = jsonencode({
    detail-type = ["AWS Console Sign In via CloudTrail", "AWS API Call via CloudTrail"]
    detail = {
      userIdentity = { type = ["Root"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "global_root_forward" {
  provider = aws.us_east_1

  rule     = aws_cloudwatch_event_rule.global_root.name
  arn      = local.home_default_bus_arn
  role_arn = aws_iam_role.global_forward.arn
}

# ---------------------------------------------------------------------------
# Cross-region bus-targets vereisen een rol: EventBridge neemt deze aan om
# het event op de bus in de thuisregio te mogen zetten. Zelfde lat als de
# Lambda-rol: exacte actie op exact een resource.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "global_forward_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    # Alleen EventBridge namens dit account (confused deputy), zelfde
    # motivatie als bij de Lambda-trust in iam.tf.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "global_forward" {
  name               = "${var.project_name}-global-forward-role"
  assume_role_policy = data.aws_iam_policy_document.global_forward_trust.json
}

data "aws_iam_policy_document" "global_forward_permissions" {
  # Alleen events op precies onze eigen default bus kunnen zetten,
  # nergens anders heen.
  statement {
    sid       = "PutEventsToHomeBus"
    actions   = ["events:PutEvents"]
    resources = [local.home_default_bus_arn]
  }
}

resource "aws_iam_role_policy" "global_forward" {
  name   = "${var.project_name}-global-forward-permissions"
  role   = aws_iam_role.global_forward.id
  policy = data.aws_iam_policy_document.global_forward_permissions.json
}
