"""Geplande audits: checks die niet aan één event hangen maar aan een toestand.

Een verouderde access key is geen gebeurtenis; die vind je alleen door
periodiek te kijken. Daarom triggert een EventBridge-schedule (1x/dag)
dezelfde Lambda in audit-modus (zie handler.py).
"""

from datetime import datetime, timezone

import boto3

from .findings import Finding

MAX_KEY_AGE_DAYS = 90


def audit_stale_keys(iam_client=None, now=None, max_age_days=MAX_KEY_AGE_DAYS) -> list[Finding]:
    """IAM-KEY-005: actieve access keys ouder dan max_age_days.

    Zonder MFA op de user is het HIGH (een gelekte key is dan meteen bruikbaar),
    mét MFA MEDIUM: MFA beschermt de console/CLI-login, maar een kale key
    werkt er gewoon omheen; oud blijft oud.

    `now` en `iam_client` zijn injecteerbaar voor tests: moto kan de
    CreateDate van een key niet verouderen, dus de klok komt van buiten.
    """
    iam = iam_client or boto3.client("iam")
    now = now or datetime.now(timezone.utc)
    findings = []

    # Paginators: ook correct als het account ooit meer dan één API-pagina
    # aan users heeft. Kost niets extra bij weinig users.
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            username = user["UserName"]
            has_mfa = bool(iam.list_mfa_devices(UserName=username)["MFADevices"])
            for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                age_days = (now - key["CreateDate"]).days
                if age_days <= max_age_days:
                    continue
                findings.append(Finding(
                    rule_id="IAM-KEY-005",
                    severity="MEDIUM" if has_mfa else "HIGH",
                    title="Access key ouder dan "
                          f"{max_age_days} dagen" + ("" if has_mfa else ", user zonder MFA"),
                    resource=f"user/{username}",
                    actor="scheduled-audit",
                    event_name="AuditStaleAccessKeys",
                    event_time=now.isoformat(),
                    region="global",  # IAM is een global service
                    account=user["Arn"].split(":")[4],
                    details={
                        "access_key_id": key["AccessKeyId"],
                        "age_days": age_days,
                        "user_has_mfa": has_mfa,
                    },
                ))
    return findings


# De lijst geplande audits, zelfde idee als RULES in rules.py.
AUDITS = [audit_stale_keys]


def run_audits() -> list[Finding]:
    findings = []
    for audit in AUDITS:
        findings.extend(audit())
    return findings
