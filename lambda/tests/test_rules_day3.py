"""Tests voor de dag-3-regels: root-gebruik, wereld-open security groups,
CloudTrail-tampering. Zelfde stijl: event in, finding of None uit."""

from src.rules import (
    rule_cloudtrail_tampering,
    rule_root_activity,
    rule_sg_open_to_world,
)


def _detail(event_name, source="ec2.amazonaws.com", **extra):
    base = {
        "eventSource": source,
        "eventName": event_name,
        "eventTime": "2026-08-24T14:00:00Z",
        "awsRegion": "eu-west-1",
        "recipientAccountId": "111111111111",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::111111111111:user/test-user",
        },
    }
    base.update(extra)
    return base


# --- IAM-ROOT-002 -----------------------------------------------------------

def test_root_console_login_raises_finding():
    detail = _detail(
        "ConsoleLogin", source="signin.amazonaws.com",
        eventType="AwsConsoleSignIn",
        sourceIPAddress="203.0.113.7",
        userIdentity={
            "type": "Root",
            "arn": "arn:aws:iam::111111111111:root",
            "sessionContext": {"attributes": {"mfaAuthenticated": "true"}},
        },
    )
    finding = rule_root_activity(detail)
    assert finding is not None
    assert finding.rule_id == "IAM-ROOT-002"
    assert finding.severity == "HIGH"
    assert finding.details["mfa_used"] == "true"
    assert finding.details["source_ip"] == "203.0.113.7"


def test_root_api_call_raises_finding():
    detail = _detail("CreateBucket", source="s3.amazonaws.com",
                     userIdentity={"type": "Root",
                                   "arn": "arn:aws:iam::111111111111:root"})
    assert rule_root_activity(detail) is not None


def test_service_acting_as_root_is_ignored():
    # AWS-service die namens het account handelt: geen mens met rootkeys.
    detail = _detail("CreateServiceLinkedRole",
                     eventType="AwsServiceEvent",
                     userIdentity={"type": "Root",
                                   "arn": "arn:aws:iam::111111111111:root"})
    assert rule_root_activity(detail) is None
    detail2 = _detail("PutObject",
                      userIdentity={"type": "Root",
                                    "arn": "arn:aws:iam::111111111111:root",
                                    "invokedBy": "config.amazonaws.com"})
    assert rule_root_activity(detail2) is None


def test_normal_iam_user_is_ignored():
    assert rule_root_activity(_detail("ConsoleLogin")) is None


# --- EC2-SG-003 -------------------------------------------------------------

def _sg_detail(perms):
    return _detail("AuthorizeSecurityGroupIngress",
                   requestParameters={"groupId": "sg-0abc123",
                                      "ipPermissions": {"items": perms}})


def test_ssh_open_to_world_is_high():
    finding = rule_sg_open_to_world(_sg_detail([{
        "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
    }]))
    assert finding is not None
    assert finding.severity == "HIGH"
    assert finding.resource == "sg-0abc123"


def test_all_traffic_ipv6_world_is_high():
    finding = rule_sg_open_to_world(_sg_detail([{
        "ipProtocol": "-1",
        "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]},
    }]))
    assert finding is not None
    assert finding.severity == "HIGH"


def test_https_open_to_world_is_medium():
    # 443 wereldwijd open is voor een webserver normaal: melden, niet gillen.
    finding = rule_sg_open_to_world(_sg_detail([{
        "ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
    }]))
    assert finding is not None
    assert finding.severity == "MEDIUM"


def test_port_range_covering_sensitive_port_is_high():
    finding = rule_sg_open_to_world(_sg_detail([{
        "ipProtocol": "tcp", "fromPort": 3000, "toPort": 4000,  # dekt 3306 én 3389
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
    }]))
    assert finding.severity == "HIGH"


def test_scoped_cidr_is_ignored():
    assert rule_sg_open_to_world(_sg_detail([{
        "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]},
    }])) is None


# --- CT-TAMPER-004 ----------------------------------------------------------

def test_stop_logging_is_critical():
    detail = _detail("StopLogging", source="cloudtrail.amazonaws.com",
                     requestParameters={"name": "secops-lab-trail"})
    finding = rule_cloudtrail_tampering(detail)
    assert finding is not None
    assert finding.severity == "CRITICAL"
    assert finding.resource == "secops-lab-trail"


def test_update_trail_is_high():
    detail = _detail("UpdateTrail", source="cloudtrail.amazonaws.com",
                     requestParameters={"name": "secops-lab-trail",
                                        "isMultiRegionTrail": False})
    finding = rule_cloudtrail_tampering(detail)
    assert finding.severity == "HIGH"
    assert finding.details["request_parameters"]["isMultiRegionTrail"] is False


def test_innocent_cloudtrail_read_is_ignored():
    detail = _detail("DescribeTrails", source="cloudtrail.amazonaws.com")
    assert rule_cloudtrail_tampering(detail) is None
