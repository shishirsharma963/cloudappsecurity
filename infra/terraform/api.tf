resource "aws_apigatewayv2_api" "fitness_api" {
  name          = "fitness-app-api-${var.environment}"
  protocol_type = "HTTP"
  description   = "Tenant-isolated API Gateway for the multi-tenant fitness application"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.fitness_api.id
  name        = "prod"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_logs.arn
    format          = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      cognitoSub     = "$context.authorizer.claims.sub"
    })
  }
}

# AWS WAF v2 configuration at the entry edge
resource "aws_wafv2_web_acl" "api_waf" {
  name        = "fitness-api-waf-${var.environment}"
  description = "Edge WAF ACL applying rate-limiting and OWASP protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "FitnessWAFMetrics"
    sampled_requests_enabled   = true
  }

  # Rate limit rule (abuse protection)
  rule {
    name     = "IPRateLimit"
    priority = 10
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPRateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  # AWS Common Vulnerabilities Managed Rule Set
  rule {
    name     = "AWSCommonManagedRules"
    priority = 20
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSCommonManagedRulesMetric"
      sampled_requests_enabled   = true
    }
  }
}

# Associate WAF Web ACL with API Gateway Stage
resource "aws_wafv2_web_acl_association" "api_waf_assoc" {
  resource_arn = aws_apigatewayv2_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}

resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/apigateway/fitness-api-${var.environment}"
  retention_in_days = 90
}
