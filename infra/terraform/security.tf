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
