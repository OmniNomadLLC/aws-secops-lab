terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.62"
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

# Aliased provider voor us-east-1: globale CloudTrail-events (root-console-
# sign-ins, IAM-calls) landen alleen daar; de detection-module forwardt ze
# naar de thuisregio (zie modules/detection/global_events.tf).
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project   = "aws-secops-lab"
      ManagedBy = "terraform"
      Owner     = "lynn"
    }
  }
}
