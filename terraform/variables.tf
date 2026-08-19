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
