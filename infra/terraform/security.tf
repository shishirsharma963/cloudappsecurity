# Database secrets manager configuration
resource "aws_secretsmanager_secret" "db_secret" {
  name                    = "fitness-db-credentials-${var.environment}"
  description             = "Secure database credentials for multi-tenant Postgres RDS"
  kms_key_id              = aws_kms_key.secret_key.arn
  recovery_window_in_days = 7
}

resource "aws_kms_key" "secret_key" {
  description             = "KMS key for encrypting Secret values"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# CREDENTIAL ROTATION: automatic 30-day rotation of the DB credentials.
# A leaked credential has a bounded useful lifetime; rotation also proves the
# application reads credentials from Secrets Manager at connect time instead
# of baking them into config (a rotation would break hardcoded consumers).

resource "aws_secretsmanager_secret_rotation" "db_secret_rotation" {
  secret_id           = aws_secretsmanager_secret.db_secret.id
  rotation_lambda_arn = aws_lambda_function.db_secret_rotator.arn

  rotation_rules {
    automatically_after_days = 30
  }
}

# Rotation Lambda: implements the standard four-step Secrets Manager contract
# (createSecret -> setSecret -> testSecret -> finishSecret) against Postgres.
resource "aws_lambda_function" "db_secret_rotator" {
  function_name = "fitness-db-secret-rotator-${var.environment}"
  description   = "Rotates the multi-tenant Postgres credentials on a 30-day schedule"
  filename      = "build/rotate_db_credentials.zip" # packaged rotation handler
  handler       = "rotate_db_credentials.lambda_handler"
  runtime       = "python3.12"
  timeout       = 60
  role          = aws_iam_role.db_secret_rotator_role.arn

  # Rotator must reach the private DB subnets to test the new credential
  vpc_config {
    subnet_ids         = [aws_subnet.private_db_a.id, aws_subnet.private_db_b.id]
    security_group_ids = [aws_security_group.app_compute_sg.id]
  }
}

# Secrets Manager (not a human, not the app) is the only allowed invoker
resource "aws_lambda_permission" "allow_secretsmanager_invoke" {
  statement_id  = "AllowSecretsManagerRotationInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.db_secret_rotator.function_name
  principal     = "secretsmanager.amazonaws.com"
  source_arn    = aws_secretsmanager_secret.db_secret.arn
}

resource "aws_iam_role" "db_secret_rotator_role" {
  name        = "fitness-db-secret-rotator-role-${var.environment}"
  description = "Workload identity for the credential rotation lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Least privilege: the rotator may manage exactly one secret and nothing else
resource "aws_iam_policy" "db_secret_rotator_policy" {
  name        = "fitness-db-secret-rotator-policy-${var.environment}"
  description = "Scoped rotation permissions for the DB credentials secret only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRotationOfDbSecretOnly"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = aws_secretsmanager_secret.db_secret.arn
      },
      {
        Sid    = "AllowSecretKmsUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.secret_key.arn
      },
      {
        Sid    = "AllowRotationTelemetry"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/lambda/fitness-db-secret-rotator-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "db_secret_rotator_attach" {
  role       = aws_iam_role.db_secret_rotator_role.name
  policy_arn = aws_iam_policy.db_secret_rotator_policy.arn
}

# WORKLOAD IDENTITY PLANE: IAM Roles & Scopes

# 1. LEAST-PRIVILEGE (GOOD): Narrowly scoped IAM role for the Import Worker compute
resource "aws_iam_role" "import_worker_role" {
  name        = "fitness-import-worker-role-${var.environment}"
  description = "Workload identity for wearable import processor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Scope rules: Allow consuming queue + database credentials, deny everything else
resource "aws_iam_policy" "import_worker_policy" {
  name        = "fitness-import-worker-policy-${var.environment}"
  description = "Least privilege permissions for import worker execution"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowQueueConsumption"
        Effect   = "Allow"
        Action   = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = "arn:aws:sqs:${var.aws_region}:*:fitness-wearable-import-queue"
      },
      {
        Sid      = "AllowDecryptDbSecrets"
        Effect   = "Allow"
        Action   = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.db_secret.arn
      },
      {
        Sid      = "AllowDbKmsKeyDecryption"
        Effect   = "Allow"
        Action   = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.secret_key.arn
      },
      {
        Sid      = "AllowWriteTelemetryLogs"
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/lambda/fitness-import-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "import_worker_attach" {
  role       = aws_iam_role.import_worker_role.name
  policy_arn = aws_iam_policy.import_worker_policy.arn
}

# 2. OVERPRIVILEGED (BAD) ROLE - For review/comparison purposes
resource "aws_iam_role" "vulnerable_app_role" {
  name        = "fitness-vulnerable-workload-role-${var.environment}"
  description = "Vulnerable workload identity holding wildcards"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "vulnerable_app_policy" {
  name        = "fitness-vulnerable-app-policy-${var.environment}"
  description = "Dangerous wildcard policy representing weak IAM architecture"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WildcardAdministrationLeakeage"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
