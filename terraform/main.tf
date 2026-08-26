module "cloudtrail" {
  source = "./modules/cloudtrail"

  project_name = var.project_name
}

module "detection" {
  source = "./modules/detection"

  project_name      = var.project_name
  alert_endpoint    = var.alert_endpoint
  alert_format      = var.alert_format
  kms_key_arn       = module.cloudtrail.kms_key_arn
  lambda_source_dir = "${path.root}/../lambda"
}
