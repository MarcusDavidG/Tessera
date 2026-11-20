# Disaster recovery runbook

Covers the multi-cloud DR design, the failover procedure and the weekly drill.
Targets: **RTO < 15 minutes**, **RPO < 5 minutes**.

## Architecture

```
                       Cloudflare Load Balancer (weighted origins)
                          │                            │
                weight 100 │                            │ weight 0 (warm)
                          ▼                            ▼
                 AWS primary API               AWS warm standby API
                 (read-write, ECS)             (read-only, ECS Fargate)
                          │                            │
                 Aurora writer                 cross-region replica
                          │                            ▲
                    pgBackRest ── WAL every 5 min ────┘
                     (S3 repo1 + GCS repo2)
```

| Component | Path | Role |
| --- | --- | --- |
| WAL archiving | `infrastructure/dr/pgbackrest.conf`, `postgresql.conf.snippet` | `archive_timeout = 300` bounds the RPO; async push keeps commits off the repository path. |
| Warm standby | `infrastructure/terraform/modules/aws/warm-standby/` | Always-on read-only API tasks pointed at the replica, so failover does not pay task placement or image pull. |
| Edge failover | `infrastructure/cloudflare/dr-failover/` | Probes the primary every 30 s; after 2 failures writes `dr:weights` to KV and flips the load-balancer pool weights. Reconciles from KV every minute. |
| Drill | `infrastructure/dr/restore_verification.sh` | Weekly: restores the latest backup + WAL, promotes, runs the read-only API checks, measures RTO/RPO, reports to PagerDuty. |
| Schedule | `.github/workflows/dr-drill.yml` | Mondays 03:00 UTC, or manual `workflow_dispatch`. |

## Measured RTO/RPO

The drill writes one JSON record per run to
`infrastructure/dr/drill-results/` and appends a row to
`infrastructure/dr/drill-results/SUMMARY.md`:

```json
{
  "run_id": "drill-20261123T030000Z",
  "result": "success",
  "rto": { "measured_seconds": 0, "target_seconds": 900, "within_target": true },
  "rpo": { "measured_seconds": 0, "target_seconds": 300, "within_target": true }
}
```

**RTO** is wall-clock time from drill start to a healthy standby
(`/health` 200), including standby creation, `pgbackrest restore --type=immediate`,
promotion and API readiness. **RPO** is the age of the newest archived WAL
segment at drill start, read from the archive bucket (`WAL_ARCHIVE_PROVIDER`
`s3` or `gcs`).

Populate the table from the artifacts of the last drill:

| Run | Result | RTO measured | RPO measured | Notes |
| --- | --- | --- | --- | --- |
| _(filled in by `SUMMARY.md` after each drill)_ | | | | |

Interpreting the numbers:

- RTO above 900 s → investigate standby task start-up (image pull, replica
  networking) and `pgbackrest restore` throughput (`process-max`).
- RPO above 300 s → check that `archive_timeout = 300` is applied and that
  `pgbackrest archive-push` is keeping up (`pgbackrest info`, CloudWatch logs).
  A failed push blocks WAL recycling; `archive-push-queue-max` protects the
  primary but silently grows the RPO.

## Failover procedure (primary down)

1. **Confirm** the alert and that the primary is unreachable:
   `curl -fsS https://api.tessera.xyz/health` from two networks.
2. **Edge failover** happens automatically after 2 failed 30 s probes. Verify:
   `curl -s https://tessera-dr-failover.<account>.workers.dev/status | jq`.
   To force it: `POST /failover` with `Authorization: Bearer $DR_ADMIN_TOKEN`.
3. **Promote the database** if the primary is not recoverable:
   ```bash
   pgbackrest --stanza=tessera --repo=repo1 restore --delta \
     --type=immediate --target-action=promote
   ```
4. **Point the standby at the promoted writer** (`replica_database_url`) and
   redeploy the standby task definition if the endpoint changed.
5. **Validate** `/health`, `/stats` and `/assets` on the standby origin.
6. **Communicate**: PagerDuty incident, status page note, and record the
   actual RTO/RPO in the incident.

## Failback procedure (primary recovered)

1. Rebuild the old primary as a replica of the promoted writer; wait until
   replication lag is under 5 s.
2. `POST /failback` (or let 3 consecutive healthy probes do it) and confirm
   `dr:weights` shows `{ "primary": 100, "standby": 0 }`.
3. Run the drill manually to verify the restored topology:
   `workflow_dispatch` on **Weekly DR Drill** with `dry_run=false`.

## Drill failure handling

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `pgbackrest restore` fails | Repository credentials, missing WAL | Check `pgbackrest check`, repository IAM, `WAL_ARCHIVE_BUCKET`. |
| Standby API never healthy | Task cannot reach the replica, wrong image | ECS service events, `/ecs/...-dr-standby-api` logs. |
| `RPO` unknown | Archive bucket not configured | Set `WAL_ARCHIVE_BUCKET` / provider secret. |
| PagerDuty not notified | `PAGERDUTY_ROUTING_KEY` unset | Add the repository secret. |

The drill tears the standby down on exit; set `KEEP_STANDBY=true` when
debugging to leave it running.
