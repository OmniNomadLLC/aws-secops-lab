"""Alert-verzending naar een HTTPS-endpoint.

Bewust urllib uit de stdlib en geen requests: nul dependencies betekent
geen lambda layers, geen supply-chain-oppervlak en een klein zip-pakket.
Het endpoint komt uit de env var ALERT_ENDPOINT (gezet door Terraform
vanuit TF_VAR_alert_endpoint) en staat dus nergens in de code of repo.
"""

import json
import logging
import os
import urllib.error
import urllib.request

from .findings import Finding

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 5  # Lambda betaalt per ms; niet eindeloos op een dood endpoint wachten.


def send_alert(finding: Finding, endpoint: str | None = None) -> bool:
    """Stuurt één finding als JSON POST. Geeft True terug bij succes.

    Geen endpoint geconfigureerd? Dan loggen we de finding alleen. Zo werkt
    het lab ook zonder Telegram-webhook en zie je alles terug in CloudWatch.
    """
    endpoint = endpoint or os.environ.get("ALERT_ENDPOINT", "")
    payload = finding.to_dict()

    if not endpoint:
        logger.warning("Geen ALERT_ENDPOINT gezet; finding alleen gelogd: %s",
                       json.dumps(payload))
        return False

    if not endpoint.startswith("https://"):
        # Alerts bevatten accountnummer en resourcenamen; die gaan niet over http.
        logger.error("ALERT_ENDPOINT is geen https-URL; alert niet verstuurd.")
        return False

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            ok = 200 <= response.status < 300
            if not ok:
                logger.error("Alert-endpoint gaf status %s", response.status)
            return ok
    except urllib.error.URLError as exc:
        logger.error("Alert versturen mislukt: %s", exc)
        return False
