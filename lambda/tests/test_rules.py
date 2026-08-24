"""Pure regellogica: event in, finding (of None) uit. Geen AWS, geen moto."""

from src.rules import evaluate, rule_s3_public_bucket


def test_canned_public_read_acl_raises_finding(acl_public_read_detail):
    finding = rule_s3_public_bucket(acl_public_read_detail)
    assert finding is not None
    assert finding.rule_id == "S3-PUBLIC-001"
    assert finding.severity == "HIGH"
    assert finding.resource == "leaky-bucket"
    assert finding.details["canned_acl"] == "public-read"


def test_allusers_grant_raises_finding(acl_allusers_grant_detail):
    finding = rule_s3_public_bucket(acl_allusers_grant_detail)
    assert finding is not None
    assert finding.details["public_grants"] == [{
        "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
        "permission": "READ",
    }]


def test_private_acl_is_ignored(acl_private_detail):
    assert rule_s3_public_bucket(acl_private_detail) is None


def test_wildcard_principal_policy_raises_finding(policy_public_detail):
    finding = rule_s3_public_bucket(policy_public_detail)
    assert finding is not None
    assert finding.title == "S3-bucketpolicy staat Principal * toe"
    assert finding.details["open_statements"][0]["action"] == "s3:GetObject"
    assert finding.details["open_statements"][0]["has_condition"] is False


def test_scoped_policy_is_ignored(policy_scoped_detail):
    assert rule_s3_public_bucket(policy_scoped_detail) is None


def test_deleting_public_access_block_always_alerts(delete_pab_detail):
    finding = rule_s3_public_bucket(delete_pab_detail)
    assert finding is not None
    assert finding.severity == "MEDIUM"


def test_weakened_public_access_block_reports_disabled_flags(weakened_pab_detail):
    finding = rule_s3_public_bucket(weakened_pab_detail)
    assert finding is not None
    assert sorted(finding.details["disabled_flags"]) == [
        "BlockPublicAcls", "IgnorePublicAcls",
    ]


def test_fully_enabled_public_access_block_is_ignored(full_pab_detail):
    assert rule_s3_public_bucket(full_pab_detail) is None


def test_unknown_event_name_is_ignored(acl_public_read_detail):
    acl_public_read_detail["eventName"] = "GetBucketAcl"
    assert rule_s3_public_bucket(acl_public_read_detail) is None


def test_evaluate_collects_findings_and_captures_actor(policy_public_detail):
    findings = evaluate(policy_public_detail)
    assert len(findings) == 1
    assert findings[0].actor == "arn:aws:iam::111111111111:user/test-user"
