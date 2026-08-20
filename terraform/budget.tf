# Kostenwaakhond. Zero-spend kan niet: dit account draagt nog LET-restanten
# met lopende kosten. $10/maand is ruim boven het lab (~$0.25/week CMK) en
# ruim onder pijnlijk; elke overschrijding is per definitie onderzoekswaardig.
resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly-cap"
  budget_type  = "COST"
  limit_amount = "10"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
