module "cloudtrail" {
  source = "./modules/cloudtrail"

  project_name = var.project_name
}
