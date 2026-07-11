resource "aws_cloudtrail" "audit_trail" {
  name                          = "fitness-app-cloudtrail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true  # Prevent tampering of log records (evidence protection)
  kms_key_id                    = aws_kms_key.trail_key.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail_bucket_policy]
}

# S3 Bucket for audit logs storage
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "fitness-app-cloudtrail-logs-${var.environment}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "block_trail_public" {
  bucket = aws_s3_bucket.trail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS Key for trail logs
resource "aws_kms_key" "trail_key" {
  description             = "KMS key for CloudTrail log file encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# Bucket policy required for CloudTrail writes
resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail_logs.arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
