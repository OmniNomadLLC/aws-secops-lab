"""Detectieregels. Elke regel is een functie: CloudTrail-detail in, Finding of None uit.

Nieuwe regel toevoegen = functie schrijven + aan RULES hangen + test erbij.
De EventBridge-rule filtert al grof op eventName; hier gebeurt de echte
beoordeling, want niet elke PutBucketAcl maakt een bucket publiek.
"""

import json

from .findings import Finding

# De twee "iedereen"-principals in S3-ACL's. AllUsers = het hele internet,
# AuthenticatedUsers = iedereen met een willekeurig AWS-account. Beide fout.
PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

# Canned ACL's die via de x-amz-acl header binnenkomen in plaats van als grants.
PUBLIC_CANNED_ACLS = {"public-read", "public-read-write"}


def _actor(detail: dict) -> str:
    identity = detail.get("userIdentity", {})
    return identity.get("arn", identity.get("principalId", "onbekend"))


def _base_finding(detail: dict, **kwargs) -> Finding:
    """De velden die elke S3-finding deelt; de regel vult titel/severity/details aan."""
    params = detail.get("requestParameters") or {}
    return Finding(
        rule_id="S3-PUBLIC-001",
        resource=params.get("bucketName", "onbekend"),
        actor=_actor(detail),
        event_name=detail.get("eventName", ""),
        event_time=detail.get("eventTime", ""),
        region=detail.get("awsRegion", ""),
        account=detail.get("recipientAccountId", ""),
        **kwargs,
    )


def _check_put_bucket_acl(detail: dict) -> Finding | None:
    """Pad 1: expliciete ACL. Publiek als een grant naar AllUsers/AuthenticatedUsers
    wijst, of als de canned ACL public-read(-write) is."""
    params = detail.get("requestParameters") or {}

    canned = (params.get("x-amz-acl") or [None])[0] if isinstance(
        params.get("x-amz-acl"), list
    ) else params.get("x-amz-acl")
    public_grants = []
    acl = params.get("AccessControlPolicy") or {}
    grants = (acl.get("AccessControlList") or {}).get("Grant") or []
    if isinstance(grants, dict):  # één grant komt als object binnen, niet als lijst
        grants = [grants]
    for grant in grants:
        uri = (grant.get("Grantee") or {}).get("URI", "")
        if uri in PUBLIC_ACL_URIS:
            public_grants.append({"uri": uri, "permission": grant.get("Permission")})

    if canned not in PUBLIC_CANNED_ACLS and not public_grants:
        return None
    return _base_finding(
        detail,
        severity="HIGH",
        title="S3-bucket-ACL opengezet voor iedereen",
        details={"canned_acl": canned, "public_grants": public_grants},
    )


def wildcard_principal_statements(policy) -> list[dict]:
    """Statements met Effect=Allow en Principal * (of {"AWS": "*"}).

    Wordt ook door de verrijking (enrich.py) gebruikt om een opgehaalde
    bucketpolicy te beoordelen: één definitie van "publiek", overal dezelfde.
    """
    if isinstance(policy, str):  # CloudTrail levert de policy soms als JSON-string
        try:
            policy = json.loads(policy)
        except (ValueError, TypeError):
            return []
    if not isinstance(policy, dict):
        return []

    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    open_statements = []
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") == "*"
        ):
            # Een Condition kán de statement inperken (bv. aws:SourceVpc); dat is
            # dan aan de mens om te beoordelen, wij melden het mee in de details.
            open_statements.append(
                {"action": stmt.get("Action"), "has_condition": "Condition" in stmt}
            )
    return open_statements


def _check_put_bucket_policy(detail: dict) -> Finding | None:
    """Pad 2: bucketpolicy met Effect=Allow en Principal * (of {"AWS": "*"})."""
    params = detail.get("requestParameters") or {}
    open_statements = wildcard_principal_statements(params.get("bucketPolicy"))
    if not open_statements:
        return None
    return _base_finding(
        detail,
        severity="HIGH",
        title="S3-bucketpolicy staat Principal * toe",
        details={"open_statements": open_statements},
    )


def _check_delete_public_access_block(detail: dict) -> Finding | None:
    """Pad 3: de vangrail weghalen is altijd meldenswaardig, ook als de bucket
    daarna (nog) niet publiek is. Dit is precies de stap die aan een lek voorafgaat."""
    return _base_finding(
        detail,
        severity="MEDIUM",
        title="Public-access-block van S3-bucket verwijderd",
    )


def _check_put_public_access_block(detail: dict) -> Finding | None:
    """Pad 4: de vangrail verzwakken: een van de vier vlaggen naar false."""
    params = detail.get("requestParameters") or {}
    config = params.get("PublicAccessBlockConfiguration") or {}
    flags = {
        key: config.get(key)
        for key in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    }
    disabled = [key for key, value in flags.items() if value is False]
    if not disabled:
        return None
    return _base_finding(
        detail,
        severity="MEDIUM",
        title="Public-access-block van S3-bucket verzwakt",
        details={"disabled_flags": disabled},
    )


# eventName -> checker. De handler kijkt alleen hierin; wat er niet in staat
# wordt genegeerd (de EventBridge-rule zou het ook niet moeten doorlaten).
S3_PUBLIC_CHECKS = {
    "PutBucketAcl": _check_put_bucket_acl,
    "PutBucketPolicy": _check_put_bucket_policy,
    "DeletePublicAccessBlock": _check_delete_public_access_block,
    "PutPublicAccessBlock": _check_put_public_access_block,
}


def rule_s3_public_bucket(detail: dict) -> Finding | None:
    check = S3_PUBLIC_CHECKS.get(detail.get("eventName", ""))
    return check(detail) if check else None


# Dag 3+: hier komen de volgende regels bij (IAM-keys zonder MFA, root-gebruik, ...).
RULES = [rule_s3_public_bucket]


def evaluate(detail: dict) -> list[Finding]:
    """Laat één CloudTrail-detail langs alle regels gaan."""
    findings = []
    for rule in RULES:
        finding = rule(detail)
        if finding:
            findings.append(finding)
    return findings
