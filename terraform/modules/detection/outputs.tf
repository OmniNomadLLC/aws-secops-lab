output "function_name" {
  description = "Naam van de detectie-Lambda, handig voor logs tail en test-invokes."
  value       = aws_lambda_function.detection.function_name
}

output "function_arn" {
  description = "ARN van de detectie-Lambda."
  value       = aws_lambda_function.detection.arn
}

output "event_rule_arn" {
  description = "De EventBridge-rule die S3-calls naar de Lambda stuurt."
  value       = aws_cloudwatch_event_rule.s3_public.arn
}

output "dlq_url" {
  description = "URL van de dead-letter queue; hier kijken als alerts uitblijven."
  value       = aws_sqs_queue.dlq.url
}
