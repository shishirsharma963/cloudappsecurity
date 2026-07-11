output "api_gateway_url" {
  value       = aws_apigatewayv2_stage.prod.invoke_url
  description = "The HTTP API Gateway URL to point the iOS mobile client to."
}

output "cognito_user_pool_id" {
  value       = aws_cognito_user_pool.user_pool.id
  description = "Cognito User Pool Identifier."
}

output "cognito_client_id" {
  value       = aws_cognito_user_pool_client.ios_client.id
  description = "Cognito App Client ID configured for PKCE on mobile."
}

output "database_kms_key_arn" {
  value       = aws_kms_key.db_key.arn
  description = "The Customer Managed Key ARN encrypting PostgreSQL storage."
}
