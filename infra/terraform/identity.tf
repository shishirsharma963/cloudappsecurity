resource "aws_cognito_user_pool" "user_pool" {
  name = "fitness-log-users-${var.environment}"

  # Enforce email-based logins (standard OIDC sub maps to user ID)
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  mfa_configuration = "OPTIONAL"
  software_token_mfa_configuration {
    # Prefer Authenticator App (TOTP) over SMS
    enabled = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true
    string_attribute_constraints {
      min_length = 5
      max_length = 128
    }
  }
}

resource "aws_cognito_user_pool_client" "ios_client" {
  name         = "fitness-ios-app-client-${var.environment}"
  user_pool_id = aws_cognito_user_pool.user_pool.id

  # Native mobile flow: OAuth PKCE (Proof Key for Code Exchange)
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]

  prevent_user_existence_errors = "ENABLED" # Prevent user enumeration in auth errors

  supported_identity_providers = ["COGNITO"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  callback_urls                        = ["cctraininglog://oauth/callback"]
  logout_urls                          = ["cctraininglog://oauth/logout"]
}

# Cognito Authorizer in API Gateway
resource "aws_apigatewayv2_authorizer" "cognito_auth" {
  api_id           = aws_apigatewayv2_api.fitness_api.id
  name             = "cognito-user-pool-authorizer"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.ios_client.id]
    issuer   = "https://${aws_cognito_user_pool.user_pool.endpoint}"
  }
}
