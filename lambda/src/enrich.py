"""Verrijking: het event zegt wat er geprobeerd is, hier checken we hoe de
bucket er NU voor staat. Dat maakt het verschil tussen "iemand deed een poging"
en "de bucket staat op dit moment open" zichtbaar in de alert.
"""

import boto3
from botocore.exceptions import ClientError

from .rules import wildcard_principal_statements


def current_public_state(bucket_name: str, s3_client=None) -> dict:
    """Vraagt S3 naar de actuele publieke status van een bucket.

    Fouten breken de alert niet: als de bucket al weg is of we mogen niet
    kijken, melden we dat als status in plaats van te crashen. Een detectie
    die sneuvelt op zijn eigen verrijking is erger dan een kale alert.
    """
    s3 = s3_client or boto3.client("s3")
    state: dict = {"bucket": bucket_name}

    # We halen de policy zelf op en beoordelen hem met onze eigen regel, in
    # plaats van get_bucket_policy_status te vragen: één definitie van
    # "publiek" (rules.py) en het is volledig testbaar met moto.
    try:
        policy_text = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        state["policy_is_public"] = bool(wildcard_principal_statements(policy_text))
    except ClientError as exc:
        # NoSuchBucketPolicy = er is geen policy, dus ook geen publieke policy.
        code = exc.response.get("Error", {}).get("Code", "")
        state["policy_is_public"] = False if code == "NoSuchBucketPolicy" else f"onbekend ({code})"

    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab["PublicAccessBlockConfiguration"]
        state["public_access_block"] = config
        state["fully_blocked"] = all(config.values())
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            # Geen configuratie = geen vangrail. Dat willen we juist weten.
            state["public_access_block"] = None
            state["fully_blocked"] = False
        else:
            state["public_access_block"] = f"onbekend ({code})"
            state["fully_blocked"] = f"onbekend ({code})"

    return state
