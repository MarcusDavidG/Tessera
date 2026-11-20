# Warm-standby API for multi-cloud disaster recovery (issue #393).
#
# Runs a second, always-warm copy of the Tessera API in ECS Fargate in
# read-only mode against the cross-region Postgres replica. On a primary
# failure the edge failover worker shifts traffic here; because the tasks are
# already running and pointed at the replica, recovery does not wait for an
# image pull or task placement (the dominant part of the RTO budget).

resource "aws_ecs_cluster" "standby" {
  name = "${var.project_name}-${var.environment}-dr-standby"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name      = "${var.project_name}-${var.environment}-dr-standby"
    DRRole    = "warm-standby"
    ManagedBy = "terraform"
  })
}

resource "aws_cloudwatch_log_group" "standby_api" {
  name              = "/ecs/${var.project_name}-${var.environment}-dr-standby-api"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_ecs_task_definition" "standby_api" {
  family                   = "${var.project_name}-${var.environment}-dr-standby-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "tessera-api"
      image     = var.api_image
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "PORT", value = "8080" },
        { name = "RWA_RPC_URL", value = var.soroban_rpc_url },
        { name = "RWA_REGISTRY_ID", value = var.registry_id },
        { name = "RWA_DIVIDEND_ID", value = var.dividend_id },
        # Read-only mode: the standby serves the replica snapshot and refuses
        # every mutating route. This is what makes it safe to keep warm.
        { name = "RWA_READ_SOURCE", value = "replica" },
        { name = "RWA_READ_ONLY_MODE", value = "true" },
        { name = "DATABASE_URL", value = var.replica_database_url },
        { name = "RUST_LOG", value = "tessera_api=info,tower_http=warn" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.standby_api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dr-standby-api"
        }
      }
      healthCheck = {
        command     = ["CMD", "/usr/local/bin/tessera-api", "healthcheck"]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "standby_api" {
  name            = "${var.project_name}-${var.environment}-dr-standby-api"
  cluster         = aws_ecs_cluster.standby.id
  task_definition = aws_ecs_task_definition.standby_api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = false
  }

  # Keep the warm copy out of the primary load balancer: traffic reaches it
  # only when the failover worker flips the pool weights.
  dynamic "load_balancer" {
    for_each = var.target_group_arn == null ? [] : [var.target_group_arn]
    content {
      target_group_arn = load_balancer.value
      container_name   = "tessera-api"
      container_port   = 8080
    }
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  health_check_grace_period_seconds = var.health_check_grace_period_seconds

  # The standby is stateless; rolling replacements must not reduce capacity
  # while a failover is in progress.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  tags = merge(var.tags, { DRRole = "warm-standby" })
}

# Alarm on the standby losing all healthy tasks: a warm standby that is not
# running cannot meet the RTO.
resource "aws_cloudwatch_metric_alarm" "standby_unhealthy" {
  alarm_name          = "${var.project_name}-${var.environment}-dr-standby-unhealthy"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Warm-standby ECS service has no running task; DR RTO is at risk."

  dimensions = {
    ClusterName = aws_ecs_cluster.standby.name
    ServiceName = aws_ecs_service.standby_api.name
  }

  tags = var.tags
}
