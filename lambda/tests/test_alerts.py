"""Alert-verzending: urllib gemockt, er verlaat niets deze machine."""

from unittest.mock import MagicMock, patch

from src.alerts import send_alert
from src.findings import Finding


def _finding() -> Finding:
    return Finding(
        rule_id="S3-PUBLIC-001", severity="HIGH", title="test",
        resource="leaky-bucket", actor="arn:aws:iam::111111111111:user/test-user",
        event_name="PutBucketAcl", event_time="2026-08-24T14:00:00Z",
        region="eu-west-1", account="111111111111",
    )


def test_without_endpoint_alert_is_only_logged(monkeypatch, caplog):
    monkeypatch.delenv("ALERT_ENDPOINT", raising=False)
    assert send_alert(_finding()) is False
    assert "leaky-bucket" in caplog.text  # de finding gaat niet stil verloren


def test_http_endpoint_is_refused(monkeypatch):
    assert send_alert(_finding(), endpoint="http://onveilig.example") is False


def test_https_post_sends_finding_as_json():
    response = MagicMock(status=200)
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    with patch("src.alerts.urllib.request.urlopen", return_value=response) as urlopen:
        assert send_alert(_finding(), endpoint="https://hooks.example/alert") is True
    request = urlopen.call_args.args[0]
    assert request.full_url == "https://hooks.example/alert"
    assert b'"rule_id": "S3-PUBLIC-001"' in request.data


def test_non_2xx_status_reports_failure():
    response = MagicMock(status=500)
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    with patch("src.alerts.urllib.request.urlopen", return_value=response):
        assert send_alert(_finding(), endpoint="https://hooks.example/alert") is False


def test_ntfy_format_sends_readable_push(monkeypatch):
    monkeypatch.setenv("ALERT_FORMAT", "ntfy")
    response = MagicMock(status=200)
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    with patch("src.alerts.urllib.request.urlopen", return_value=response) as urlopen:
        assert send_alert(_finding(), endpoint="https://ntfy.sh/topic") is True
    request = urlopen.call_args.args[0]
    # urllib normaliseert headernamen naar Titlecase
    assert request.get_header("Title") == "[HIGH] test"
    assert request.get_header("Priority") == "high"
    assert "shield" in request.get_header("Tags")
    assert b"leaky-bucket" in request.data
    assert request.get_header("Content-type") is None  # geen JSON-header bij ntfy


def test_json_stays_default_format(monkeypatch):
    monkeypatch.delenv("ALERT_FORMAT", raising=False)
    response = MagicMock(status=200)
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=False)
    with patch("src.alerts.urllib.request.urlopen", return_value=response) as urlopen:
        send_alert(_finding(), endpoint="https://hooks.example/alert")
    assert urlopen.call_args.args[0].get_header("Content-type") == "application/json"
