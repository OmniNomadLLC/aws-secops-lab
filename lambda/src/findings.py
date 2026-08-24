"""Het datamodel voor een detectie: één Finding per geraakte regel.

Bewust een dataclass en geen dict: de velden liggen vast, typos in keys
vallen meteen om in tests in plaats van stilletjes lege alerts te sturen.
"""

from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    rule_id: str          # stabiel ID, bv. "S3-PUBLIC-001"; hier filter je later op
    severity: str         # LOW / MEDIUM / HIGH / CRITICAL
    title: str            # één regel voor in de alert
    resource: str         # wat is er geraakt (bucketnaam, user, ...)
    actor: str            # wie deed het (IAM-arn uit het event)
    event_name: str       # de API-call die de detectie triggerde
    event_time: str       # tijdstip uit het event, niet "nu" (kan replay zijn)
    region: str
    account: str
    details: dict = field(default_factory=dict)  # regelspecifieke context

    def to_dict(self) -> dict:
        return asdict(self)
