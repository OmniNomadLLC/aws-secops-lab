terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  backend "s3" {
    bucket         = "secops-lab-tfstate-19920a31"
    key            = "global/terraform.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "secops-lab-tflock"
    encrypt        = true
  }
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
