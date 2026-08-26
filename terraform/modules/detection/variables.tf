variable "project_name" {
  description = "Naamprefix, komt uit de hoofdstack."
  type        = string
}

variable "alert_endpoint" {
  description = "HTTPS-endpoint voor alerts; wordt env var ALERT_ENDPOINT van de Lambda. Sensitive: komt via TF_VAR_alert_endpoint, staat nergens in de repo."
  type        = string
  sensitive   = true
  default     = ""
}

variable "kms_key_arn" {
  description = "De lab-CMK (uit de cloudtrail-module) voor env-var-encryptie en de loggroep."
  type        = string
}

variable "lambda_source_dir" {
  description = "Map met de Lambda-code; alleen src/ gaat het zip-pakket in."
  type        = string
}

variable "log_retention_days" {
  description = "Bewaartermijn CloudWatch-logs, zelfde motivatie als bij cloudtrail (CKV_AWS_338)."
  type        = number
  default     = 365
}

variable "alert_format" {
  description = "Vorm van de alert: \"json\" (generieke webhook) of \"ntfy\" (leesbare push met Title/Priority/Tags)."
  type        = string
  default     = "json"

  validation {
    condition     = contains(["json", "ntfy"], var.alert_format)
    error_message = "alert_format moet json of ntfy zijn."
  }
}
