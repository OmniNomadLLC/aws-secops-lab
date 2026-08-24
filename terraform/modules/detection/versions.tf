# De module pint zijn eigen extra provider (archive, voor het zip-pakket);
# aws erft hij van de hoofdstack.
terraform {
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}
