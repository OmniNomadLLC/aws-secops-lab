terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Dag 1: eerst lokaal draaien, daarna deze backend aanzetten.
  # De bucket en de locktable maak je eenmalig met een aparte mini-stack (bootstrap),
  # anders heb je een kip-en-ei-probleem met de state.
  # backend "s3" {
  #   bucket         = "secops-lab-tfstate-<uniek-suffix>"
  #   key            = "global/terraform.tfstate"
  #   region         = "eu-west-1"
  #   dynamodb_table = "secops-lab-tflock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "aws-secops-lab"
      ManagedBy = "terraform"
      Owner     = "lynn"
    }
  }
}
