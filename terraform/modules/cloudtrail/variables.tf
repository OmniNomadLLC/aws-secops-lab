variable "project_name" {
  description = "Naamprefix, komt uit de hoofdstack."
  type        = string
}

variable "log_retention_days" {
  description = "Bewaartermijn voor CloudWatch-logs en de S3-trail-logs. 365 om aan CKV_AWS_338 te voldoen; kost niets extra omdat het lab ruim daarvoor wordt vernietigd."
  type        = number
  default     = 365
}
