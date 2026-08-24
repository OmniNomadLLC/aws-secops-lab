output "function_name" {
  description = "Naam van de detectie-Lambda, handig voor logs tail en test-invokes."
  value       = aws_lambda_function.detection.function_name
}

output "function_arn" {
  description = "ARN van de detectie-Lambda."
  value       = aws_lambda_function.detection.arn
}

output "event_rule_arns" {
  description = "Alle EventBridge-rules die events naar de Lambda sturen."
  value = merge(
    { for key, rule in aws_cloudwatch_event_rule.detection : key => rule.arn },
    { daily-audit = aws_cloudwatch_event_rule.daily_audit.arn },
  )
}

output "dlq_url" {
  description = "URL van de dead-letter queue; hier kijken als alerts uitblijven."
  value       = aws_sqs_queue.dlq.url
}
