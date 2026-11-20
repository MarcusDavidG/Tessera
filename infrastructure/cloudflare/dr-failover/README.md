# Tessera DR failover worker (issue #393)

Edge health checking and DNS-weight failover for the multi-cloud DR design.

```
              every 30s (Durable Object alarm)
   ┌────────────────────────────────────────────────────┐
   │  GET PRIMARY_HEALTH_URL  (5s timeout)              │
   │  2 consecutive failures ──▶ active = standby       │
   │  3 consecutive successes ─▶ active = primary       │
   └───────────────┬────────────────────────────────────┘
                   │ writes
                   ▼
        Workers KV  dr:active_region / dr:weights
                   │ reconciled every minute by the cron trigger
                   ▼
   Cloudflare Load Balancer pool origin weights (primary/standby)
```

## Why it is built this way

- **30-second cadence**: Cron Triggers cannot fire more often than once per
  minute, so the probe loop runs on a Durable Object alarm. The DO also owns
  the consecutive-failure counters, which a stateless Worker would lose.
- **KV is the source of truth**: the DO writes the intended weights to KV, and
  the once-a-minute scheduled handler re-applies them to the pool. A failed
  Cloudflare API call during the failover is retried, not lost.
- **Flap resistance**: failover needs 2 failures, failback needs 3 successes.
- **Bounded probe cost**: one request per 30 s, 5 s timeout, and no writes
  unless a transition happens.

## Endpoints

| Path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | — | Worker liveness. |
| `GET /status` | — | Active region, streak counters, KV weights. |
| `POST /probe` | `DR_ADMIN_TOKEN` | Run one probe immediately. |
| `POST /failover` | `DR_ADMIN_TOKEN` | Force the standby active. |
| `POST /failback` | `DR_ADMIN_TOKEN` | Force the primary active. |

## Bindings

| Binding | Purpose |
| --- | --- |
| `HEALTH_MONITOR` | Durable Object namespace (`HealthMonitor`). |
| `DR_STATE` | KV: `dr:active_region`, `dr:weights`, `dr:updated_at`. |
| `PRIMARY_HEALTH_URL` | Primary `/health` endpoint. |
| `FAILURE_THRESHOLD` / `RECOVERY_THRESHOLD` | Flap thresholds (default 2 / 3). |
| `PROBE_TIMEOUT_MS` | Probe timeout (default 5000). |
| `CF_ACCOUNT_ID`, `CF_POOL_ID` | Load Balancer pool to re-weight. |
| `CF_API_TOKEN` (secret) | Token with Load Balancer pool edit permission. |
| `DR_ADMIN_TOKEN` (secret) | Manual failover authorisation. |

## Deploy

```bash
cd infrastructure/cloudflare/dr-failover
npx wrangler kv namespace create DR_STATE   # paste the id into wrangler.toml
npx wrangler secret put CF_API_TOKEN
npx wrangler secret put DR_ADMIN_TOKEN
npx wrangler deploy
```

## Verify

```bash
curl -s https://tessera-dr-failover.<account>.workers.dev/status | jq
curl -s -X POST -H "Authorization: Bearer $DR_ADMIN_TOKEN" \
  https://tessera-dr-failover.<account>.workers.dev/probe | jq
```

The weight flip is visible in the pool's origins; combined with the 30 s probe
interval and the 5 s timeout, detection-to-DNS-change is bounded at about
65 s — well inside the 15-minute RTO budget. The remaining RTO is database
restore + standby promotion, measured by the weekly drill
(`infrastructure/dr/restore_verification.sh`).
