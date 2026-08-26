variable "aws_region" {
  description = "AWS-regio. eu-west-1 (Ierland) is dichtbij en heeft alles wat we nodig hebben."
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Prefix voor alle resourcenamen, zodat je in de console meteen ziet wat bij dit lab hoort."
  type        = string
  default     = "secops-lab"
}

variable "alert_endpoint" {
  description = "HTTPS-endpoint waar findings naartoe gaan. Nooit hardcoden, via TF_VAR_alert_endpoint."
  type        = string
  sensitive   = true
  default     = ""
}

variable "budget_alert_email" {
  description = "Ontvanger van budgetalerts. Via TF_VAR_budget_alert_email, niet in de repo."
  type        = string
  sensitive   = true
}

variable "alert_format" {
  description = "Alertvorm: json (webhook) of ntfy (push naar de ntfy-app, zelfde patroon als de sanity-scan)."
  type        = string
  default     = "json"
}
