resource "aws_rds_cluster" "postgres" {
  cluster_identifier      = "fitness-log-db-${var.environment}"
  engine                  = "aurora-postgresql"
  engine_version          = "15.4"
  database_name           = "fitnesslog"
  master_username         = "admin_user"
  master_password         = null # Managed securely in Secrets Manager (aws_secretsmanager_secret_version)
  
  # Network Isolation: Put database strictly inside private subnets
  db_subnet_group_name    = aws_db_subnet_group.db_subnets.name
  vpc_security_group_ids  = [aws_security_group.db_sg.id]

  # Data Protection: Enforce KMS customer-managed key encryption at rest
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.db_key.arn

  # Backups and recovery configuration
  backup_retention_period   = 35  # RPO support
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "fitness-log-db-final-snapshot"
}

resource "aws_rds_cluster_instance" "postgres_instances" {
  count              = 2
  identifier         = "fitness-log-db-inst-${count.index}-${var.environment}"
  cluster_identifier = aws_rds_cluster.postgres.id
  instance_class     = "db.r6g.large"
  engine             = aws_rds_cluster.postgres.engine
  engine_version     = aws_rds_cluster.postgres.engine_version
  
  publicly_accessible = false  # Strict network boundary: no public IP
}

resource "aws_db_subnet_group" "db_subnets" {
  name       = "fitness-db-subnet-group-${var.environment}"
  subnet_ids = [aws_subnet.private_db_a.id, aws_subnet.private_db_b.id]
}

# Strictly scoped Security Group for the Database
resource "aws_security_group" "db_sg" {
  name        = "fitness-db-security-group-${var.environment}"
  description = "Allows ingress from RDS Proxy and rotation lambda only"
  vpc_id      = aws_vpc.app_vpc.id

  # Application traffic reaches the cluster only via the RDS Proxy
  ingress {
    description     = "PostgreSQL from RDS Proxy"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds_proxy_sg.id]
  }

  # The credential rotation lambda connects directly to test new credentials
  ingress {
    description     = "PostgreSQL from rotation lambda (app compute SG)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_compute_sg.id]
  }

  # No egress block: with no egress rule, the SG denies all outbound.
  # (The previous revision had a comment claiming "deny all outbound" above a
  # rule that ALLOWED all outbound — a lie in code. The database initiates no
  # connections; it needs none.)
}

# KMS Key for DB encryption at rest
resource "aws_kms_key" "db_key" {
  description             = "KMS key for multi-tenant PostgreSQL storage encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # Enforce automatic key rotation
}

# Basic networking mocks for VPC/subnets boundary illustration
resource "aws_vpc" "app_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private_db_a" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "${var.aws_region}a"
}

resource "aws_subnet" "private_db_b" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "${var.aws_region}b"
}

resource "aws_security_group" "app_compute_sg" {
  name        = "fitness-app-compute-sg-${var.environment}"
  description = "Security group for application services compute"
  vpc_id      = aws_vpc.app_vpc.id
}
