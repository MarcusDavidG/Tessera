# Warm-standby API module (issue #393)

An always-warm, read-only copy of the Tessera API in ECS Fargate, pointed at
the cross-region PostgreSQL replica. The DR failover worker flips the
Cloudflare Load Balancer weights to it when the primary fails, so recovery
costs a DNS/weight change plus database promotion — not a cold start.

## What it provisions

| Resource | Purpose |
| --- | --- |
| `aws_ecs_cluster.standby` | Dedicated cluster (Container Insights on). |
| `aws_ecs_task_definition.standby_api` | API task with `RWA_READ_SOURCE=replica` and `RWA_READ_ONLY_MODE=true`, `DATABASE_URL` pointing at the replica. |
| `aws_ecs_service.standby_api` | `desired_count` warm tasks, circuit breaker, rolling deployment that never drops below 100% healthy. |
| `aws_cloudwatch_metric_alarm.standby_unhealthy` | Pages when no standby task is running (RTO at risk). |
| `aws_cloudwatch_log_group.standby_api` | Standby logs. |

The task is deliberately **not** attached to the primary target group unless
`target_group_arn` is supplied; traffic only reaches it through the failover
worker's pool weight change.

## Usage

```hcl
module "warm_standby" {
  source = "../../modules/aws/warm-standby"

  project_name         = "tessera"
  environment          = "prod"
  aws_region           = "us-east-1"
  private_subnet_ids   = module.vpc.private_subnet_ids
  security_group_ids   = [module.security_groups.ecs_security_group_id]
  execution_role_arn   = module.iam.ecs_task_execution_role_arn
  task_role_arn        = module.iam.ecs_task_role_arn
  api_image            = var.api_image
  replica_database_url = var.replica_database_url # sensitive
  registry_id          = var.registry_id
  dividend_id          = var.dividend_id
}
```

`environments/prod` wires this module behind `enable_warm_standby`; the weekly
drill applies it with `-target=module.warm_standby`.

## Inputs / outputs

All inputs are documented in `variables.tf`. The outputs (`cluster_name`,
`service_name`, `task_definition_arn`, `log_group_name`) are consumed by the
drill script to wait for the service to stabilise and to collect logs.
