# aws-secops-lab

Security-automation lab op AWS, geprovisioned met Terraform, aangestuurd met Python.

Doel: van "AWS en Terraform staan op mijn profiel" naar "hier is de repo, met commits en datums".
Dit project is er om de skills op de XpertDirect-kaart en het cv echt waar te maken, en om te
leren. Het mikt bewust op precies de skills die security-automation-rollen vragen.

## Waarom dit project en niet iets anders

Job 1924 (Security Automation Engineer, Duitsland) vroeg: Python, AWS, Terraform, IAM,
REST APIs, DevSecOps. Dit project raakt alle zes in een opzet die klein genoeg is om af te
maken en echt genoeg om te laten zien.

| Gevraagde skill | Waar die hier zit |
|---|---|
| Terraform | de volledige infra staat in `terraform/`, niets met de hand aangeklikt |
| AWS | VPC, S3, IAM, CloudTrail, Lambda, EventBridge (alles free tier) |
| IAM | least-privilege rollen per functie, geen wildcard-policies |
| Python | de detectie-Lambda in `lambda/` |
| REST APIs | findings gaan naar een HTTP-endpoint en naar Telegram |
| DevSecOps | CI die de IaC scant met tfsec en checkov voor er iets uitrolt |

## Wat het doet

CloudTrail- en Config-events komen binnen op EventBridge. Een Python-Lambda evalueert ze tegen
een set securityregels en stuurt findings door. Regels om mee te beginnen:

- S3-bucket die publiek leesbaar wordt gemaakt
- IAM-policy met `"Action": "*"` of `"Resource": "*"`
- root-account login
- access key ouder dan 90 dagen
- security group die 0.0.0.0/0 op 22 of 3389 openzet

Dat is hetzelfde patroon als de n8n-vloot: event binnen, regel evalueren, mens waarschuwen.
Alleen dan op AWS en in Terraform in plaats van in een workflow-UI.

## Weekplan

| Dag | Doel | Resultaat |
|---|---|---|
| 1 | AWS-account + Terraform backend | `terraform apply` draait, state in S3 met DynamoDB-lock |
| 2 | IAM en logging | CloudTrail aan, least-privilege rollen, tfsec groen |
| 3 | Eerste detectie | Lambda vangt "S3 bucket public" en stuurt een alert |
| 4 | Regels uitbreiden | vijf regels, unit tests met moto |
| 5 | CI/CD | GitHub Actions: fmt, validate, plan, tfsec, checkov, pytest |
| 6 | Documentatie | architectuurschets, threat model, README met screenshots |
| 7 | Opruimen | `terraform destroy`, kosten op nul, repo publiek |

## Wat jij zelf moet doen

Een **AWS-account aanmaken** (free tier). Accounts registreren en wachtwoorden invullen doe ik
niet, dat is aan jou. Daarna een IAM-user met programmatic access voor Terraform, en de keys in
`~/.aws/credentials` of als env-vars. De keys komen nooit in deze repo.

## Kosten

Alles binnen free tier. CloudTrail heeft één gratis trail, Lambda 1M requests gratis,
S3 5 GB. De DynamoDB-locktable is on-demand en kost bij dit volume vrijwel niets.
Aan het eind van de week `terraform destroy` en het staat weer op nul.
