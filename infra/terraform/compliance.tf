# CONFIGURATION DRIFT DETECTION (AWS Config)
#
# Preventive controls (private subnets, publicly_accessible = false) only
# describe the *intended* state. AWS Config continuously evaluates the *actual*
# state, so a console click or errant Terraform apply that exposes the database
# or a bucket becomes an alert within minutes instead of a finding at the next
# audit. This is the detective complement to the preventive rules in
# database.tf and storage.tf.

resource "aws_config_configuration_recorder" "drift_recorder" {
  name     = "fitness-config-recorder-${var.environment}"
  role_arn = aws_iam_role.config_recorder_role.arn

  recording_group {
    all_supported = true
  }
}

resource "aws_config_delivery_channel" "drift_delivery" {
  name           = "fitness-config-delivery-${var.environment}"
  s3_bucket_name = aws_s3_bucket.trail_logs.id # reuse the hardened audit-log bucket
  depends_on     = [aws_config_configuration_recorder.drift_recorder]
}

resource "aws_config_configuration_recorder_status" "drift_recorder_on" {
  name       = aws_config_configuration_recorder.drift_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.drift_delivery]
}

resource "aws_iam_role" "config_recorder_role" {
  name = "fitness-config-recorder-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_recorder_managed" {
  role       = aws_iam_role.config_recorder_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Managed rule: flags any RDS instance that becomes publicly accessible.
# This is the drift alarm for the `publicly_accessible = false` invariant.
resource "aws_config_config_rule" "rds_not_public" {
  name        = "fitness-rds-instance-public-access-check-${var.environment}"
  description = "NON_COMPLIANT if the multi-tenant database gains a public endpoint"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.drift_recorder]
}

# Managed rule: database snapshots must never be shared publicly
# (a classic exfiltration path that bypasses every network control).
resource "aws_config_config_rule" "rds_snapshots_not_public" {
  name        = "fitness-rds-snapshots-public-prohibited-${var.environment}"
  description = "NON_COMPLIANT if any DB snapshot is shared publicly"

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.drift_recorder]
}

# Managed rule: no bucket in the account may allow public reads.
resource "aws_config_config_rule" "s3_no_public_read" {
  name        = "fitness-s3-public-read-prohibited-${var.environment}"
  description = "NON_COMPLIANT if any S3 bucket permits public read access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.drift_recorder]
}

# ALERTING PATH: Config compliance change -> EventBridge -> SNS (security team)

resource "aws_sns_topic" "security_drift_alerts" {
  name              = "fitness-security-drift-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.secret_key.arn # encrypt alert payloads at rest
}

resource "aws_cloudwatch_event_rule" "config_noncompliance" {
  name        = "fitness-config-noncompliance-${var.environment}"
  description = "Fires when any Config rule transitions to NON_COMPLIANT"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "notify_security_team" {
  rule      = aws_cloudwatch_event_rule.config_noncompliance.name
  target_id = "security-drift-sns"
  arn       = aws_sns_topic.security_drift_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.security_drift_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_drift_alerts.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.config_noncompliance.arn
          }
        }
      }
    ]
  })
}
