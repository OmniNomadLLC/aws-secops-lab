terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Geen backend-blok. Dit is de stack die de backend zelf maakt, dus zijn state
  # blijft lokaal (terraform.tfstate in deze map, gitignored). Kip en ei.
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "aws-secops-lab"
      ManagedBy = "terraform"
      Owner     = "lynn"
      Stack     = "bootstrap"
    }
  }
}
