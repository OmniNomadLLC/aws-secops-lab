"""Verrijking tegen een door moto geëmuleerde S3-API.

moto draait de AWS-API in-memory: boto3-calls gedragen zich als echt,
maar er verlaat niets deze machine en het kost niets.
"""

import boto3
import pytest
from moto import mock_aws

from src.enrich import current_public_state

REGION = "eu-west-1"


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name=REGION)
        client.create_bucket(
            Bucket="lab-bucket",
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )
        yield client


def test_bucket_without_policy_or_pab_is_reported_unblocked(s3):
    state = current_public_state("lab-bucket", s3_client=s3)
    assert state["policy_is_public"] is False
    assert state["public_access_block"] is None
    assert state["fully_blocked"] is False


def test_fully_blocked_bucket_is_reported_blocked(s3):
    s3.put_public_access_block(
        Bucket="lab-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    state = current_public_state("lab-bucket", s3_client=s3)
    assert state["fully_blocked"] is True


def test_public_policy_is_reported_public(s3):
    s3.put_bucket_policy(
        Bucket="lab-bucket",
        Policy=(
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",'
            ' "Principal": "*", "Action": "s3:GetObject",'
            ' "Resource": "arn:aws:s3:::lab-bucket/*"}]}'
        ),
    )
    state = current_public_state("lab-bucket", s3_client=s3)
    assert state["policy_is_public"] is True


def test_missing_bucket_does_not_crash(s3):
    state = current_public_state("bestaat-niet", s3_client=s3)
    assert "onbekend" in str(state["policy_is_public"])
