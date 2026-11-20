/**
 * Tessera DR failover worker (issue #393).
 *
 * Every 30 seconds a Durable Object probes the primary API's `/health`. Two
 * consecutive failures flip the active region to the warm standby; three
 * consecutive successes flip it back. The decision is written to Workers KV
 * (`dr:active_region`, `dr:weights`) and reconciled into the Cloudflare Load
 * Balancer pool origin weights, which is the DNS-level RTO trigger.
 *
 * Why a Durable Object: Cron Triggers cannot run more often than once a
 * minute, and a stateless fetch would lose the consecutive-failure counters.
 * The DO owns the state and its own alarm chain, so the 30 s cadence survives
 * isolates being evicted.
 *
 * KV is the source of truth for weights. The scheduled handler reconciles the
 * pool from KV every minute, so a failed API call to Cloudflare during a
 * failover is retried instead of leaving traffic pinned to a dead region.
 *
 * Bindings:
 *   HEALTH_MONITOR  Durable Object namespace (class HealthMonitor)
 *   DR_STATE        Workers KV namespace
 *   PRIMARY_HEALTH_URL, STANDBY_HEALTH_URL, FAILURE_THRESHOLD,
 *   RECOVERY_THRESHOLD, PROBE_TIMEOUT_MS, CF_ACCOUNT_ID, CF_POOL_ID
 *   CF_API_TOKEN (secret), DR_ADMIN_TOKEN (secret, manual overrides)
 */

const CF_API = 'https://api.cloudflare.com/client/v4';

export const PROBE_INTERVAL_MS = 30_000;
export const PROBE_TIMEOUT_MS = 5_000;
export const DEFAULT_FAILURE_THRESHOLD = 2;
export const DEFAULT_RECOVERY_THRESHOLD = 3;

const PRIMARY = 'primary';
const STANDBY = 'standby';

/** Load-balancer origin weights for the active region. */
export function weightsFor(activeRegion) {
  return activeRegion === STANDBY
    ? { primary: 0, standby: 100 }
    : { primary: 100, standby: 0 };
}

/**
 * Pure failover state machine: given the last state and this probe's verdict,
 * return the next state and whether a transition happened.
 */
export function decide(state, healthy, config = {}) {
  const failureThreshold = config.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD;
  const recoveryThreshold = config.recoveryThreshold ?? DEFAULT_RECOVERY_THRESHOLD;
  const current = state && state.active_region === STANDBY ? STANDBY : PRIMARY;

  const next = {
    active_region: current,
    consecutive_failures: healthy ? 0 : (state?.consecutive_failures ?? 0) + 1,
    consecutive_successes: healthy ? (state?.consecutive_successes ?? 0) + 1 : 0,
    last_failover_at: state?.last_failover_at ?? null,
  };

  let transition = null;
  if (healthy && current === STANDBY && next.consecutive_successes >= recoveryThreshold) {
    next.active_region = PRIMARY;
    transition = 'failback';
  } else if (!healthy && current === PRIMARY && next.consecutive_failures >= failureThreshold) {
    next.active_region = STANDBY;
    transition = 'failover';
  }
  return { next, transition };
}

function envInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function config(env) {
  return {
    primaryHealthUrl: env.PRIMARY_HEALTH_URL,
    failureThreshold: envInt(env.FAILURE_THRESHOLD, DEFAULT_FAILURE_THRESHOLD),
    recoveryThreshold: envInt(env.RECOVERY_THRESHOLD, DEFAULT_RECOVERY_THRESHOLD),
    probeTimeoutMs: envInt(env.PROBE_TIMEOUT_MS, PROBE_TIMEOUT_MS),
  };
}

function json(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

/**
 * Push the supplied origin weights into the Cloudflare Load Balancer pool.
 * Best effort: a failure is reported to the caller but must not break the
 * probe loop, because the next scheduled reconcile retries from KV.
 */
export async function applyPoolWeights(env, weights, fetchImpl = fetch) {
  const token = env.CF_API_TOKEN;
  const accountId = env.CF_ACCOUNT_ID;
  const poolId = env.CF_POOL_ID;
  if (!token || !accountId || !poolId) {
    return { applied: false, reason: 'cloudflare_api_not_configured' };
  }

  const poolUrl = `${CF_API}/accounts/${accountId}/load_balancers/pools/${poolId}`;
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  };

  let pool;
  try {
    const current = await fetchImpl(poolUrl, { headers });
    if (!current.ok) return { applied: false, reason: `pool_read_${current.status}` };
    pool = await current.json();
  } catch (error) {
    return { applied: false, reason: `pool_read_failed: ${error.message}` };
  }

  const origins = (pool?.result?.origins ?? []).map((origin) => ({
    ...origin,
    weight: Object.prototype.hasOwnProperty.call(weights, origin.name)
      ? weights[origin.name]
      : origin.weight,
  }));

  try {
    const patched = await fetchImpl(poolUrl, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ origins }),
    });
    return { applied: patched.ok, status: patched.status };
  } catch (error) {
    return { applied: false, reason: `pool_patch_failed: ${error.message}` };
  }
}

/** Read the weights stored in KV (source of truth for the reconciler). */
export async function readWeights(env) {
  try {
    const stored = await env.DR_STATE.get('dr:weights', 'json');
    if (stored && typeof stored === 'object') return stored;
  } catch {
    // Fall through to the default.
  }
  return weightsFor(PRIMARY);
}

/** Reconcile the Cloudflare pool with the weights currently in KV. */
export async function reconcile(env, fetchImpl = fetch) {
  const weights = await readWeights(env);
  return applyPoolWeights(env, weights, fetchImpl);
}

export class HealthMonitor {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async snapshot() {
    const stored = await this.state.storage.get('status');
    return {
      active_region: stored?.active_region ?? PRIMARY,
      consecutive_failures: stored?.consecutive_failures ?? 0,
      consecutive_successes: stored?.consecutive_successes ?? 0,
      last_probe_at: stored?.last_probe_at ?? null,
      last_failover_at: stored?.last_failover_at ?? null,
    };
  }

  async ensureAlarm() {
    const existing = await this.state.storage.getAlarm();
    if (existing === null) {
      await this.state.storage.setAlarm(Date.now() + PROBE_INTERVAL_MS);
    }
  }

  async checkPrimary() {
    const cfg = config(this.env);
    if (!cfg.primaryHealthUrl) return false;
    try {
      const response = await fetch(cfg.primaryHealthUrl, {
        signal: AbortSignal.timeout(cfg.probeTimeoutMs),
        headers: { accept: 'application/json' },
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /** Persist a region change to KV, then try to apply it at the edge. */
  async publish(state) {
    const weights = weightsFor(state.active_region);
    try {
      await this.env.DR_STATE.put('dr:active_region', state.active_region);
      await this.env.DR_STATE.put('dr:weights', JSON.stringify(weights));
      await this.env.DR_STATE.put('dr:updated_at', state.last_probe_at ?? '');
    } catch (error) {
      console.error(`[dr] KV write failed: ${error.message}`);
    }
    const result = await applyPoolWeights(this.env, weights);
    if (!result.applied) {
      console.warn(`[dr] pool weight update deferred: ${result.reason ?? result.status}`);
    }
    return result;
  }

  async probe() {
    const cfg = config(this.env);
    const state = await this.snapshot();
    const healthy = await this.checkPrimary();
    const { next, transition } = decide(state, healthy, cfg);
    next.last_probe_at = new Date().toISOString();

    if (transition) {
      next.last_failover_at = next.last_probe_at;
      console.log(`[dr] ${transition}: active region -> ${next.active_region}`);
      await this.publish(next);
    }
    await this.state.storage.put('status', next);
    return { ...next, transition, healthy };
  }

  async setRegion(region) {
    if (region !== PRIMARY && region !== STANDBY) {
      return json(400, { error: 'invalid_region' });
    }
    const state = await this.snapshot();
    state.active_region = region;
    state.last_failover_at = new Date().toISOString();
    state.last_probe_at = state.last_failover_at;
    state.consecutive_failures = 0;
    state.consecutive_successes = 0;
    await this.state.storage.put('status', state);
    await this.publish(state);
    return json(200, state);
  }

  async fetch(request) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/ensure':
        await this.ensureAlarm();
        return json(200, { scheduled: true, interval_ms: PROBE_INTERVAL_MS });
      case '/probe':
        return json(200, await this.probe());
      case '/set':
        return this.setRegion(url.searchParams.get('region'));
      case '/status':
      default:
        return json(200, await this.snapshot());
    }
  }

  async alarm() {
    try {
      const result = await this.probe();
      console.log(`[dr] probe healthy=${result.healthy} region=${result.active_region}`);
    } catch (error) {
      console.error(`[dr] probe failed: ${error.message}`);
    } finally {
      await this.state.storage.setAlarm(Date.now() + PROBE_INTERVAL_MS);
    }
  }
}

function monitor(env) {
  const id = env.HEALTH_MONITOR.idFromName('tessera-primary');
  return env.HEALTH_MONITOR.get(id);
}

function isAuthorized(request, env) {
  if (!env.DR_ADMIN_TOKEN) return false;
  const header = request.headers.get('authorization') || '';
  return header === `Bearer ${env.DR_ADMIN_TOKEN}`;
}

export default {
  async scheduled(controller, env, ctx) {
    const stub = monitor(env);
    ctx.waitUntil(stub.fetch('https://dr.internal/ensure'));
    ctx.waitUntil(reconcile(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const stub = monitor(env);

    if (url.pathname === '/healthz') {
      return json(200, { ok: true });
    }
    if (url.pathname === '/status') {
      const [status, region, weights] = await Promise.all([
        stub.fetch('https://dr.internal/status').then((response) => response.json()),
        env.DR_STATE.get('dr:active_region'),
        readWeights(env),
      ]);
      return json(200, { ...status, kv_active_region: region, kv_weights: weights });
    }
    if (url.pathname === '/failover' || url.pathname === '/failback') {
      if (!isAuthorized(request, env)) {
        return json(401, { error: 'unauthorized' });
      }
      const region = url.pathname === '/failover' ? STANDBY : PRIMARY;
      const response = await stub.fetch(`https://dr.internal/set?region=${region}`);
      return response;
    }
    if (url.pathname === '/probe' && request.method === 'POST') {
      if (!isAuthorized(request, env)) {
        return json(401, { error: 'unauthorized' });
      }
      return stub.fetch('https://dr.internal/probe');
    }
    return json(404, { error: 'not_found' });
  },
};
