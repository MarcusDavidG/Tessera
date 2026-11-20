variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "tessera"
}

variable "environment" {
  type        = string
  description = "Target environment (used by the drill: prod)"
  default     = "prod"
}

variable "aws_region" {
  type        = string
  description = "AWS region hosting the warm standby"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets that can reach the Postgres replica"
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security groups for the standby tasks (egress to the replica and RPC)"
}

variable "execution_role_arn" {
  type        = string
  description = "ECS task execution role ARN"
}

variable "task_role_arn" {
  type        = string
  description = "ECS task role ARN"
}

variable "api_image" {
  type        = string
  description = "API container image URI"
}

variable "replica_database_url" {
  type        = string
  description = "Connection URL of the cross-region Postgres replica (read-only)"
  sensitive   = true
}

variable "soroban_rpc_url" {
  type        = string
  description = "Soroban RPC URL"
  default     = "https://soroban-testnet.stellar.org"
}

variable "registry_id" {
  type        = string
  description = "Registry contract ID"
}

variable "dividend_id" {
  type        = string
  description = "Dividend contract ID"
}

variable "api_cpu" {
  type        = string
  description = "CPU units for the standby task"
  default     = "256"
}

variable "api_memory" {
  type        = string
  description = "Memory (MB) for the standby task"
  default     = "512"
}

variable "desired_count" {
  type        = number
  description = "Number of warm standby tasks to keep running"
  default     = 1
}

variable "target_group_arn" {
  type        = string
  description = "Optional second target group of the failover load balancer"
  default     = null
}

variable "health_check_grace_period_seconds" {
  type        = number
  description = "Grace period before ECS health checks count"
  default     = 30
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch retention for standby logs"
  default     = 14
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to every resource"
  default     = {}
}
