output "cluster_arn" {
  description = "ARN of the warm-standby ECS cluster"
  value       = aws_ecs_cluster.standby.arn
}

output "cluster_name" {
  description = "Name of the warm-standby ECS cluster"
  value       = aws_ecs_cluster.standby.name
}

output "service_name" {
  description = "Warm-standby ECS service name"
  value       = aws_ecs_service.standby_api.name
}

output "task_definition_arn" {
  description = "Warm-standby task definition ARN"
  value       = aws_ecs_task_definition.standby_api.arn
}

output "log_group_name" {
  description = "CloudWatch log group of the standby API"
  value       = aws_cloudwatch_log_group.standby_api.name
}
