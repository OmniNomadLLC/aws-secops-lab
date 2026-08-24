# aws-secops-lab

Event-driven securitydetectie op AWS: volledig in Terraform, detectielogica in Python,
gescand en getest in CI vóór elke uitrol.

Doel: van "AWS en Terraform staan op mijn profiel" naar "hier is de repo, met commits en datums".
Dit project is er om de skills op de XpertDirect-kaart en het cv echt waar te maken, en om te
leren. Het mikt bewust op precies de skills die security-automation-rollen vragen.

## Architectuur

```
                       AWS-account
  ┌──────────────────────────────────────────────────────┐
  │  API-call (S3 / EC2 / IAM / root / CloudTrail)       │
  │        │                                             │
  │        ▼                                             │
  │  CloudTrail (multi-region, CMK, log validation)      │
  │        │                                             │
  │        ▼                                             │
  │  EventBridge ── 4 patroonrules + 1 dagelijkse        │
  │        │        schedule (grof filter bij AWS)       │
  │        ▼                                             │
  │  Lambda secops-lab-detection (Python, arm64)         │
  │    • regels evalueren (fijn filter)                  │
  │    • verrijken met actuele resource-status           │
  │    • alert → HTTPS-endpoint (ALERT_ENDPOINT)         │
  │    • mislukte events → SQS-DLQ                       │
  └──────────────────────────────────────────────────────┘
```

Het grove filter (welke eventNames überhaupt relevant zijn) zit in de EventBridge-patronen,
dus irrelevante calls kosten geen Lambda-invocaties. Het fijne oordeel (is deze
`PutBucketAcl` echt publiek?) zit in Python, waar het unit-testbaar is.

## Detectieregels

| Regel | Wat | Severity | Live bewezen |
|---|---|---|---|
| S3-PUBLIC-001 | bucket publiek via ACL, policy met `Principal:*`, of public-access-block weg/verzwakt | HIGH/MEDIUM | finding 10 s na PAB-verzwakking |
| IAM-ROOT-002 | elk handmatig root-gebruik (AWS-service-acties uitgezonderd) | HIGH | unit tests |
| EC2-SG-003 | security group open naar 0.0.0.0/0 of ::/0; HIGH op beheer-/db-poorten of al het verkeer | HIGH/MEDIUM | finding 3 s na wereld-open SSH |
| CT-TAMPER-004 | CloudTrail gestopt/verwijderd (CRITICAL) of aangepast (HIGH) | CRITICAL/HIGH | unit tests |
| IAM-KEY-005 | actieve access key >90 dagen; HIGH als de user geen MFA heeft (dagelijkse audit) | HIGH/MEDIUM | vond direct 3 echte stale keys |

Regels zijn data: een lijst functies in `lambda/src/rules.py` (events) en `lambda/src/audit.py`
(geplande toestandschecks). Een regel toevoegen = één functie + één EventBridge-patroonentry +
tests.

## Threat model (kort)

**Wat beschermen we:** de integriteit van het AWS-account zelf: geen stille publieke data-
exposure, geen onopgemerkt gebruik van te machtige credentials, geen uitgeschakelde audit-trail.

**Tegen wie/wat:**

| Dreiging | Detectie | Beperking |
|---|---|---|
| Gelekte key maakt een bucket publiek (exfiltratie-voorbereiding) | S3-PUBLIC-001, binnen seconden | detectie ≠ preventie; de vangrail zelf is het account-brede public-access-block |
| Aanvaller met rootcredentials | IAM-ROOT-002 | console-sign-ins landen als globaal event in us-east-1; deze stack vangt regionale root-API-calls. Cross-region forwarding staat op de roadmap |
| Beheerpoort open naar het internet (instap voor brute force) | EC2-SG-003 | alleen `AuthorizeSecurityGroupIngress`; bestaande oude regels vangt alleen een (toekomstige) audit |
| Aanvaller zet de camera's uit vóór de inbraak | CT-TAMPER-004 | als de aanvaller ook de Lambda/EventBridge kan slopen is de detectie zelf het doelwit; dat vergt org-level guardrails (SCP's), buiten scope van één account |
| Verouderde, MFA-loze credentials als stille achterdeur | IAM-KEY-005, dagelijks | audit draait 1x/dag; een key die 's ochtends lekt zie je pas 's nachts |

**Aannames:** de deploy-user is vertrouwd; de state-bucket is versleuteld en niet publiek;
alerts bevatten accountnummer en resourcenamen en gaan daarom uitsluitend over https.

**Detectie beschermt zichzelf:** trail-tampering is zelf een CRITICAL-regel, de Lambda-rol kan
niets aanmaken of wijzigen (alleen lezen + loggen + eigen DLQ), en mislukte events bewaart de
DLQ 14 dagen.

## Waarom dit project en niet iets anders

Job 1924 (Security Automation Engineer, Duitsland) vroeg: Python, AWS, Terraform, IAM,
REST APIs, DevSecOps. Dit project raakt alle zes in een opzet die klein genoeg is om af te
maken en echt genoeg om te laten zien.

| Gevraagde skill | Waar die hier zit |
|---|---|
| Terraform | de volledige infra in `terraform/`, modules, S3-backend met locking, niets met de hand aangeklikt |
| AWS | S3, IAM, KMS, CloudTrail, Lambda, EventBridge, SQS, X-Ray, Budgets |
| IAM | least-privilege rollen per functie: exacte acties op exacte resources, elke wildcard gemotiveerd in de code |
| Python | detectie-engine + 38 unit tests (moto) in `lambda/` |
| REST APIs | findings als JSON-POST naar een HTTPS-endpoint (Telegram-webhook) |
| DevSecOps | CI scant de IaC met tfsec en checkov en draait pytest vóór er iets uitrolt |

## Scanner-beleid

tfsec en checkov zijn groen. Vindingen kennen drie uitkomsten, nooit stil onderdrukken:

1. **Echt oplossen** — CMK-encryptie, X-Ray, DLQ, retentie 365d, EventBridge-notificaties.
2. **Eerlijk voldoen zonder kosten** — SSE-SQS op de DLQ, arm64.
3. **Beargumenteerd afwijzen** — de motivatie staat als comment op de skip-regel ín de code
   (KMS-key-policy false positives, onmogelijke reserved concurrency door accountquota,
   noodzakelijke wildcards voor detectie-reads).

## Weekplan

| Dag | Doel | Status |
|---|---|---|
| 1 | Backend, CloudTrail-stack, budget, CI met scanners | ✅ 2026-08-24 |
| 2 | Detectie-Lambda + regel 1 (publieke S3-bucket), moto-tests, module met least-privilege rol | ✅ 2026-08-24, live bewezen |
| 3 | Regels 2 t/m 5 + dagelijkse audit-schedule | ✅ 2026-08-24, live bewezen |
| 4 | Telegram-alerts end-to-end op de telefoon | ⏳ wacht op webhook-URL |
| 5 | (opgeschoven) verdieping: cross-region root-events, SG-audit | |
| 6 | Documentatie: architectuur, threat model, README | ✅ dit document |
| 7 | `terraform destroy`, kosten op nul, repo publiek | |

## Draaien

```bash
export AWS_PROFILE=secops-lab
export TF_VAR_budget_alert_email=...   # nooit in de repo
export TF_VAR_alert_endpoint=...       # https, optioneel: leeg = log-only
terraform -chdir=terraform init
terraform -chdir=terraform plan
pytest lambda -q
```

## Kosten

Vrijwel alles binnen free tier: één gratis CloudTrail-trail, Lambda 1M requests/maand gratis,
X-Ray 100k traces gratis, SQS/EventBridge verwaarloosbaar. De enige vaste post is de CMK
(~$1/maand, bewust: échte encryptie in plaats van scanner-suppressie). Maandbudget van $10 met
e-mailalerts staat als vangnet in Terraform. Aan het eind: `terraform destroy` en alles op nul.
