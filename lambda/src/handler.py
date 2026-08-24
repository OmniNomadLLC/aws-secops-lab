"""Lambda-entrypoint. EventBridge levert één CloudTrail-event per invocatie.

Flow: event -> regels evalueren -> finding verrijken met de actuele
bucketstatus -> alert versturen. De return-waarde is er voor tests en
handmatige invokes; EventBridge zelf doet er niets mee.
"""

import logging

from .alerts import send_alert
from .enrich import current_public_state
from .rules import evaluate

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: dict, context=None) -> dict:
    # EventBridge stopt het CloudTrail-record in "detail"; bij een directe
    # test-invoke kan er ook een kaal record binnenkomen, dan pakken we dat.
    detail = event.get("detail", event)

    findings = evaluate(detail)
    if not findings:
        logger.info("Geen regels geraakt voor eventName=%s", detail.get("eventName"))
        return {"findings": 0, "alerts_sent": 0}

    alerts_sent = 0
    for finding in findings:
        # Verrijking pas ná de detectie: alleen S3-API-calls doen als er echt
        # iets te melden valt, dat houdt de Lambda snel en de rol klein.
        if finding.rule_id.startswith("S3-"):
            finding.details["current_state"] = current_public_state(finding.resource)
        logger.info("Finding %s: %s op %s door %s",
                    finding.rule_id, finding.title, finding.resource, finding.actor)
        if send_alert(finding):
            alerts_sent += 1

    return {"findings": len(findings), "alerts_sent": alerts_sent}
