variable "aws_region" {
  type        = string
  description = "The target AWS region for deployment."
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Target deployment environment context."
  default     = "production"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the isolated application VPC."
  default     = "10.0.0.0/16"
}
