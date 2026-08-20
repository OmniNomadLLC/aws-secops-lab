variable "project_name" {
  description = "Naamprefix, komt uit de hoofdstack."
  type        = string
}

variable "log_retention_days" {
  description = "Bewaartermijn voor CloudWatch-logs en de S3-trail-logs. Kort houden: dit is een lab, geen compliance-archief."
  type        = number
  default     = 30
}
