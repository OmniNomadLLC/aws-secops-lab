output "trail_arn" {
  description = "ARN van de CloudTrail-trail."
  value       = aws_cloudtrail.main.arn
}

output "log_group_name" {
  description = "CloudWatch-loggroep waar de trail naartoe schrijft; hier gaan de detectieregels straks op kijken."
  value       = aws_cloudwatch_log_group.trail.name
}

output "trail_bucket" {
  description = "S3-bucket met de ruwe trail-logs."
  value       = aws_s3_bucket.trail_logs.id
}

output "kms_key_arn" {
  description = "De lab-CMK; wordt hergebruikt door de detection-module (env vars + loggroep)."
  value       = aws_kms_key.cloudtrail.arn
}
