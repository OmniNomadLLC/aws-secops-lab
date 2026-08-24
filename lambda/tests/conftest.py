"""Gedeelde testdata: realistische CloudTrail-details zoals EventBridge ze levert.

De structuur komt uit de CloudTrail-documentatie en echte events; velden die
de regels niet gebruiken zijn weggelaten om de fixtures leesbaar te houden.
"""

import pytest


def _base_detail(event_name: str, request_parameters: dict) -> dict:
    return {
        "eventVersion": "1.09",
        "eventSource": "s3.amazonaws.com",
        "eventName": event_name,
        "eventTime": "2026-08-24T14:00:00Z",
        "awsRegion": "eu-west-1",
        "recipientAccountId": "111111111111",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::111111111111:user/test-user",
            "principalId": "AIDAEXAMPLE",
        },
        "requestParameters": request_parameters,
    }


@pytest.fixture
def acl_public_read_detail():
    """PutBucketAcl met canned ACL public-read (via de x-amz-acl header)."""
    return _base_detail("PutBucketAcl", {
        "bucketName": "leaky-bucket",
        "x-amz-acl": ["public-read"],
    })


@pytest.fixture
def acl_allusers_grant_detail():
    """PutBucketAcl met een expliciete grant aan AllUsers."""
    return _base_detail("PutBucketAcl", {
        "bucketName": "leaky-bucket",
        "AccessControlPolicy": {
            "AccessControlList": {
                "Grant": [{
                    "Grantee": {
                        "xsi:type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }],
            },
        },
    })


@pytest.fixture
def acl_private_detail():
    """PutBucketAcl die alleen de eigenaar rechten geeft: géén finding."""
    return _base_detail("PutBucketAcl", {
        "bucketName": "tidy-bucket",
        "AccessControlPolicy": {
            "AccessControlList": {
                "Grant": [{
                    "Grantee": {"xsi:type": "CanonicalUser", "ID": "abc123"},
                    "Permission": "FULL_CONTROL",
                }],
            },
        },
    })


@pytest.fixture
def policy_public_detail():
    """PutBucketPolicy met Principal * : de klassieke publieke lees-policy.
    CloudTrail levert bucketPolicy als JSON-string, dus dat doen wij ook."""
    return _base_detail("PutBucketPolicy", {
        "bucketName": "leaky-bucket",
        "bucketPolicy": (
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",'
            ' "Principal": "*", "Action": "s3:GetObject",'
            ' "Resource": "arn:aws:s3:::leaky-bucket/*"}]}'
        ),
    })


@pytest.fixture
def policy_scoped_detail():
    """PutBucketPolicy met een specifieke principal: géén finding."""
    return _base_detail("PutBucketPolicy", {
        "bucketName": "tidy-bucket",
        "bucketPolicy": (
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",'
            ' "Principal": {"AWS": "arn:aws:iam::111111111111:role/reader"},'
            ' "Action": "s3:GetObject", "Resource": "arn:aws:s3:::tidy-bucket/*"}]}'
        ),
    })


@pytest.fixture
def delete_pab_detail():
    return _base_detail("DeleteBucketPublicAccessBlock", {"bucketName": "leaky-bucket"})


@pytest.fixture
def weakened_pab_detail():
    """PutPublicAccessBlock waarbij twee van de vier vlaggen uitgaan."""
    return _base_detail("PutBucketPublicAccessBlock", {
        "bucketName": "leaky-bucket",
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    })


@pytest.fixture
def full_pab_detail():
    """PutPublicAccessBlock met alles aan: dit is juist goed, géén finding."""
    return _base_detail("PutBucketPublicAccessBlock", {
        "bucketName": "tidy-bucket",
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    })
