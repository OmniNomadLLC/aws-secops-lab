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


def event_finding(detail: dict, **kwargs) -> Finding:
    """De velden die elke event-finding deelt (dader, tijd, regio, account);
    de regel levert rule_id, severity, titel, resource en details."""
    return Finding(
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
    return event_finding(
        detail,
        rule_id="S3-PUBLIC-001",
        resource=params.get("bucketName", "onbekend"),
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
    return event_finding(
        detail,
        rule_id="S3-PUBLIC-001",
        resource=params.get("bucketName", "onbekend"),
        severity="HIGH",
        title="S3-bucketpolicy staat Principal * toe",
        details={"open_statements": open_statements},
    )


def _check_delete_public_access_block(detail: dict) -> Finding | None:
    """Pad 3: de vangrail weghalen is altijd meldenswaardig, ook als de bucket
    daarna (nog) niet publiek is. Dit is precies de stap die aan een lek voorafgaat."""
    params = detail.get("requestParameters") or {}
    return event_finding(
        detail,
        rule_id="S3-PUBLIC-001",
        resource=params.get("bucketName", "onbekend"),
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
    return event_finding(
        detail,
        rule_id="S3-PUBLIC-001",
        resource=params.get("bucketName", "onbekend"),
        severity="MEDIUM",
        title="Public-access-block van S3-bucket verzwakt",
        details={"disabled_flags": disabled},
    )


# eventName -> checker. De handler kijkt alleen hierin; wat er niet in staat
# wordt genegeerd (de EventBridge-rule zou het ook niet moeten doorlaten).
# Let op: CloudTrail noemt de public-access-block-calls anders dan de S3-API
# (PutBucketPublicAccessBlock i.p.v. PutPublicAccessBlock); empirisch
# vastgesteld op 2026-08-24 via lookup-events. Beide varianten staan erin
# zodat de regel ook werkt als AWS de naamgeving ooit gelijktrekt.
S3_PUBLIC_CHECKS = {
    "PutBucketAcl": _check_put_bucket_acl,
    "PutBucketPolicy": _check_put_bucket_policy,
    "DeleteBucketPublicAccessBlock": _check_delete_public_access_block,
    "DeletePublicAccessBlock": _check_delete_public_access_block,
    "PutBucketPublicAccessBlock": _check_put_public_access_block,
    "PutPublicAccessBlock": _check_put_public_access_block,
}


def rule_s3_public_bucket(detail: dict) -> Finding | None:
    check = S3_PUBLIC_CHECKS.get(detail.get("eventName", ""))
    return check(detail) if check else None


def rule_root_activity(detail: dict) -> Finding | None:
    """IAM-ROOT-002: elk handmatig gebruik van het root-account.

    Root hoort in de kluis te liggen; elke actie ermee is meldenswaardig.
    AwsServiceEvents worden overgeslagen: dat zijn acties die AWS zelf
    namens het account uitvoert (bv. een key-rotatie van een managed
    service), geen mens die met root-credentials werkt.
    """
    identity = detail.get("userIdentity") or {}
    if identity.get("type") != "Root":
        return None
    if detail.get("eventType") == "AwsServiceEvent" or identity.get("invokedBy"):
        return None
    return event_finding(
        detail,
        rule_id="IAM-ROOT-002",
        severity="HIGH",
        title="Root-account gebruikt",
        resource=identity.get("arn", "root"),
        details={
            "event_type": detail.get("eventType"),
            "mfa_used": (identity.get("sessionContext") or {})
            .get("attributes", {})
            .get("mfaAuthenticated"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    )


# Poorten waarop "open naar de wereld" vrijwel altijd fout is: beheer (SSH/RDP),
# databases en caches. HTTP/HTTPS (80/443) staan er bewust niet in: dat is
# voor een webserver legitiem en zou alleen ruis geven.
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _world_open_permissions(params: dict) -> list[dict]:
    """AuthorizeSecurityGroupIngress-items die vanaf het hele internet mogen."""
    items = ((params.get("ipPermissions") or {}).get("items")) or []
    hits = []
    for perm in items:
        cidrs = [r.get("cidrIp") for r in ((perm.get("ipRanges") or {}).get("items") or [])]
        cidrs += [r.get("cidrIpv6") for r in ((perm.get("ipv6Ranges") or {}).get("items") or [])]
        world = [c for c in cidrs if c in WORLD_CIDRS]
        if not world:
            continue
        protocol = str(perm.get("ipProtocol", ""))
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")
        # Protocol -1 = al het verkeer; poorten zijn dan niet van toepassing.
        all_traffic = protocol == "-1"
        sensitive = all_traffic or (
            from_port is not None
            and to_port is not None
            and any(from_port <= p <= to_port for p in SENSITIVE_PORTS)
        )
        hits.append({
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "cidrs": world,
            "sensitive": sensitive,
        })
    return hits


def rule_sg_open_to_world(detail: dict) -> Finding | None:
    """EC2-SG-003: security-group-regel opengezet voor 0.0.0.0/0 of ::/0.

    HIGH als er een gevoelige poort (of al het verkeer) in zit, anders MEDIUM:
    ook een onschuldig ogende wereld-open poort is het melden waard, maar hoeft
    niemand wakker voor te bellen.
    """
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return None
    params = detail.get("requestParameters") or {}
    hits = _world_open_permissions(params)
    if not hits:
        return None
    return event_finding(
        detail,
        rule_id="EC2-SG-003",
        severity="HIGH" if any(h["sensitive"] for h in hits) else "MEDIUM",
        title="Security group opengezet naar het internet",
        resource=params.get("groupId", "onbekend"),
        details={"world_open": hits},
    )


# CloudTrail-calls die de detectie zelf blind kunnen maken. Stoppen of
# verwijderen is CRITICAL (logging is dan wég); aanpassen is HIGH (kan
# een verkapte verzwakking zijn, bv. management events uitzetten).
TRAIL_TAMPER_EVENTS = {
    "StopLogging": "CRITICAL",
    "DeleteTrail": "CRITICAL",
    "UpdateTrail": "HIGH",
    "PutEventSelectors": "HIGH",
}


def rule_cloudtrail_tampering(detail: dict) -> Finding | None:
    """CT-TAMPER-004: iemand zit aan de audit-logging zelf.

    Dit is de belangrijkste regel van allemaal: de eerste stap van een
    aanvaller met genoeg rechten is het uitzetten van de camera's.
    """
    severity = TRAIL_TAMPER_EVENTS.get(detail.get("eventName", ""))
    if not severity:
        return None
    params = detail.get("requestParameters") or {}
    return event_finding(
        detail,
        rule_id="CT-TAMPER-004",
        severity=severity,
        title="CloudTrail-logging gestopt of aangepast",
        resource=params.get("name", "onbekend"),
        details={"request_parameters": params},
    )


RULES = [
    rule_s3_public_bucket,
    rule_root_activity,
    rule_sg_open_to_world,
    rule_cloudtrail_tampering,
]


def evaluate(detail: dict) -> list[Finding]:
    """Laat één CloudTrail-detail langs alle regels gaan."""
    findings = []
    for rule in RULES:
        finding = rule(detail)
        if finding:
            findings.append(finding)
    return findings
