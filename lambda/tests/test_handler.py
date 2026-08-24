"""De hele keten: EventBridge-envelope in, alert eruit. S3 via moto,
het alert-endpoint gemockt zodat er niets naar buiten gaat."""

from unittest.mock import patch

import boto3
from moto import mock_aws

from src import handler as handler_module

REGION = "eu-west-1"


def _eventbridge_envelope(detail: dict) -> dict:
    """EventBridge verpakt het CloudTrail-record; de handler moet zelf uitpakken."""
    return {
        "version": "0",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "region": REGION,
        "detail": detail,
    }


def test_public_policy_event_triggers_enriched_alert(policy_public_detail, monkeypatch):
    monkeypatch.setenv("ALERT_ENDPOINT", "https://hooks.example/alert")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)

    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(
            Bucket="leaky-bucket",
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )
        with patch.object(handler_module, "send_alert", return_value=True) as sender:
            result = handler_module.handler(
                _eventbridge_envelope(policy_public_detail))

    assert result == {"findings": 1, "alerts_sent": 1}
    finding = sender.call_args.args[0]
    # De verrijking heeft de actuele bucketstatus toegevoegd aan de finding.
    assert finding.details["current_state"]["bucket"] == "leaky-bucket"
    assert finding.details["current_state"]["fully_blocked"] is False


def test_benign_event_sends_nothing(full_pab_detail, monkeypatch):
    monkeypatch.setenv("ALERT_ENDPOINT", "https://hooks.example/alert")
    with patch.object(handler_module, "send_alert") as sender:
        result = handler_module.handler(_eventbridge_envelope(full_pab_detail))
    assert result == {"findings": 0, "alerts_sent": 0}
    sender.assert_not_called()
