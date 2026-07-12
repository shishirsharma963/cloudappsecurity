# PRIVATE CONNECTIVITY PLANE
#
# The private subnets deliberately have NO route to the internet (no NAT
# Gateway, no internet gateway route). But workloads in those subnets still
# need AWS control-plane APIs: the rotation lambda must call Secrets Manager,
# compute must decrypt via KMS, workers must poll SQS, and everything ships
# logs to CloudWatch. Without the endpoints below, those calls would hang and
# time out — "private subnet" without PrivateLink is an architecture that
# cannot actually run. Interface endpoints keep that traffic on the AWS
# backbone with resource policies, instead of hairpinning through a NAT
# Gateway that also opens a generic egress path for exfiltration.

# Explicit route tables for the private subnets: local VPC routes only.
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.app_vpc.id
  # No 0.0.0.0/0 route on purpose: workloads here can reach the VPC and the
  # endpoints below, and nothing else. Egress control by construction.
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_db_a.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_db_b.id
  route_table_id = aws_route_table.private_rt.id
}

# Security group for the interface endpoints: HTTPS from workloads only.
resource "aws_security_group" "vpc_endpoints_sg" {
  name        = "fitness-vpc-endpoints-sg-${var.environment}"
  description = "Allows HTTPS to AWS service endpoints from app compute"
  vpc_id      = aws_vpc.app_vpc.id

  ingress {
    description     = "TLS from application compute workloads"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app_compute_sg.id]
  }
}

# Interface endpoints (PrivateLink) for every AWS API the private workloads use.
locals {
  interface_endpoint_services = {
    secretsmanager = "Rotation lambda + app credential reads"
    kms            = "Envelope decryption of secrets and data keys"
    logs           = "CloudWatch Logs delivery from private compute"
    sqs            = "Wearable import queue consumption"
    sts            = "Workload role assumption (token exchange)"
    events         = "EventBridge alert emission from detection hooks"
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = aws_vpc.app_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_db_a.id, aws_subnet.private_db_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Purpose = each.value
  }
}

# S3 is a Gateway endpoint: free, attaches to the route table, no ENI needed.
resource "aws_vpc_endpoint" "s3_gateway" {
  vpc_id            = aws_vpc.app_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_rt.id]
}

# CONNECTION POOLING (RDS Proxy)
#
# Lambda scales to hundreds of concurrent executions; Postgres does not scale
# to hundreds of concurrent connections. Without a proxy, a traffic spike
# exhausts max_connections and takes the database down for everyone — a
# self-inflicted denial of service. RDS Proxy multiplexes Lambda connections
# onto a small pooled set and fetches DB credentials from Secrets Manager
# itself, so application code never handles the password at all.

resource "aws_security_group" "rds_proxy_sg" {
  name        = "fitness-rds-proxy-sg-${var.environment}"
  description = "Accepts app connections and forwards to the DB cluster"
  vpc_id      = aws_vpc.app_vpc.id

  ingress {
    description     = "PostgreSQL from application compute"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_compute_sg.id]
  }

  egress {
    description     = "PostgreSQL to the database cluster only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db_sg.id]
  }
}

resource "aws_db_proxy" "postgres_proxy" {
  name                   = "fitness-db-proxy-${var.environment}"
  engine_family          = "POSTGRESQL"
  role_arn               = aws_iam_role.rds_proxy_role.arn
  vpc_subnet_ids         = [aws_subnet.private_db_a.id, aws_subnet.private_db_b.id]
  vpc_security_group_ids = [aws_security_group.rds_proxy_sg.id]
  require_tls            = true
  idle_client_timeout    = 900

  auth {
    auth_scheme = "SECRETS"
    iam_auth    = "REQUIRED" # apps authenticate to the proxy with IAM, not passwords
    secret_arn  = aws_secretsmanager_secret.db_secret.arn
  }
}

resource "aws_db_proxy_default_target_group" "proxy_targets" {
  db_proxy_name = aws_db_proxy.postgres_proxy.name

  connection_pool_config {
    max_connections_percent      = 90
    max_idle_connections_percent = 10
  }
}

resource "aws_db_proxy_target" "cluster_target" {
  db_proxy_name         = aws_db_proxy.postgres_proxy.name
  target_group_name     = aws_db_proxy_default_target_group.proxy_targets.name
  db_cluster_identifier = aws_rds_cluster.postgres.cluster_identifier
}

resource "aws_iam_role" "rds_proxy_role" {
  name = "fitness-rds-proxy-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "rds_proxy_policy" {
  name        = "fitness-rds-proxy-policy-${var.environment}"
  description = "Proxy may read exactly the DB credential secret"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowReadDbSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.db_secret.arn
      },
      {
        Sid      = "AllowSecretKmsDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.secret_key.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_proxy_attach" {
  role       = aws_iam_role.rds_proxy_role.name
  policy_arn = aws_iam_policy.rds_proxy_policy.arn
}
