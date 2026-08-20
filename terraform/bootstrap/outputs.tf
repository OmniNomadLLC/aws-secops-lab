output "state_bucket_name" {
  description = "Naam van de state-bucket. Deze waarde vul je in het backend-blok van terraform/versions.tf."
  value       = aws_s3_bucket.tfstate.id
}

output "lock_table_name" {
  description = "Naam van de DynamoDB-locktable."
  value       = aws_dynamodb_table.tflock.name
}

# Handig bij stap 2: dit blok kun je letterlijk overnemen in terraform/versions.tf.
output "backend_block" {
  description = "Kant-en-klaar backend-blok voor de hoofdstack."
  value       = <<-EOT
    backend "s3" {
      bucket         = "${aws_s3_bucket.tfstate.id}"
      key            = "global/terraform.tfstate"
      region         = "${var.aws_region}"
      dynamodb_table = "${aws_dynamodb_table.tflock.name}"
      encrypt        = true
    }
  EOT
}
