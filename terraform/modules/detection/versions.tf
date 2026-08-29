# De module pint zijn eigen extra provider (archive, voor het zip-pakket);
# aws erft hij van de hoofdstack. De alias us_east_1 is nodig voor
# global_events.tf: een module mag maar een required_providers-blok hebben,
# dus de alias-declaratie staat hier en niet daar.
terraform {
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.us_east_1]
    }
  }
}
