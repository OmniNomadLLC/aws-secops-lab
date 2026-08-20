variable "aws_region" {
  description = "Regio voor de state-bucket en de locktable. Moet gelijk zijn aan de regio in het backend-blok van de hoofdstack."
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Prefix voor de resourcenamen, gelijk aan de hoofdstack."
  type        = string
  default     = "secops-lab"
}

variable "noncurrent_version_retention_days" {
  description = "Hoe lang oude state-versies bewaard blijven. Versioning is je vangnet bij een kapotte state, maar oude versies moeten wel opgeruimd worden anders groeit de bucket eindeloos door."
  type        = number
  default     = 90
}
