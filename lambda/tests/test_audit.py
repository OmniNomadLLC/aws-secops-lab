"""IAM-KEY-005 tegen een door moto geëmuleerde IAM. moto kan de CreateDate
van een key niet verouderen, dus de klok wordt geïnjecteerd (now=)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import boto3
from moto import mock_aws

from src.audit import audit_stale_keys
from src import handler as handler_module


def _iam_with_user(username, with_mfa=False):
    iam = boto3.client("iam", region_name="eu-west-1")
    iam.create_user(UserName=username)
    iam.create_access_key(UserName=username)
    if with_mfa:
        device = iam.create_virtual_mfa_device(VirtualMFADeviceName=username)
        iam.enable_mfa_device(
            UserName=username,
            SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
            AuthenticationCode1="123456", AuthenticationCode2="654321",
        )
    return iam


@mock_aws
def test_old_key_without_mfa_is_high():
    iam = _iam_with_user("backup-ish-user")
    future = datetime.now(timezone.utc) + timedelta(days=150)
    findings = audit_stale_keys(iam_client=iam, now=future)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "IAM-KEY-005"
    assert finding.severity == "HIGH"
    assert finding.resource == "user/backup-ish-user"
    assert finding.details["age_days"] >= 149
    assert finding.details["user_has_mfa"] is False


@mock_aws
def test_old_key_with_mfa_is_medium():
    iam = _iam_with_user("careful-user", with_mfa=True)
    future = datetime.now(timezone.utc) + timedelta(days=100)
    findings = audit_stale_keys(iam_client=iam, now=future)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


@mock_aws
def test_fresh_key_is_ignored():
    iam = _iam_with_user("new-user")
    findings = audit_stale_keys(iam_client=iam,
                                now=datetime.now(timezone.utc) + timedelta(days=30))
    assert findings == []


@mock_aws
def test_inactive_old_key_is_ignored():
    iam = _iam_with_user("retired-user")
    key_id = iam.list_access_keys(UserName="retired-user")["AccessKeyMetadata"][0]["AccessKeyId"]
    iam.update_access_key(UserName="retired-user", AccessKeyId=key_id, Status="Inactive")
    findings = audit_stale_keys(iam_client=iam,
                                now=datetime.now(timezone.utc) + timedelta(days=365))
    assert findings == []


def test_scheduled_event_routes_to_audit(monkeypatch):
    monkeypatch.delenv("ALERT_ENDPOINT", raising=False)
    with patch.object(handler_module, "run_audits", return_value=[]) as audits:
        result = handler_module.handler({"detail-type": "Scheduled Event",
                                         "source": "aws.events"})
    audits.assert_called_once()
    assert result == {"findings": 0, "alerts_sent": 0}
