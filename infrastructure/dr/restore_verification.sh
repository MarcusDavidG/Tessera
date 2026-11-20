#!/usr/bin/env bash
# =============================================================================
# Tessera — automated disaster-recovery drill (issue #393)
#
# Runs the weekly DR exercise end to end:
#
#   1. measure RPO (age of the newest archived WAL segment) before starting;
#   2. spin up the warm-standby ECS Fargate service from Terraform;
#   3. restore the latest pgBackRest backup + WAL into the standby database;
#   4. wait for the read-only API to answer /health, then run the API test
#      suite against it (read-only assertions only);
#   5. measure RTO (wall clock from drill start to a healthy standby);
#   6. report the result to PagerDuty and write a JSON + Markdown record under
#      infrastructure/dr/drill-results/;
#   7. tear the standby back down (unless KEEP_STANDBY=true).
#
# Modes:
#   DR_MODE=pgbackrest (default)  full warm-standby drill described above
#   DR_MODE=snapshot              legacy logical-restore verification; delegates
#                                 to infrastructure/scripts/dr_test.sh
#
# Environment:
#   RTO_TARGET_SECONDS        default 900   (15 min)
#   RPO_TARGET_SECONDS        default 300   (5 min)
#   STANDBY_TERRAFORM_DIR     default ../terraform/environments/prod
#   STANDBY_TERRAFORM_TARGET  default module.warm_standby
#   STANDBY_API_URL           health endpoint of the standby API
#   API_TEST_CMD              extra read-only assertions (shell), e.g.
#                             'cargo test --manifest-path api/Cargo.toml --test api'
#   PGBACKREST_STANZA         default tessera
#   PGBACKREST_CONFIG         default /etc/pgbackrest/pgbackrest.conf
#   PGBACKREST_REPO           default repo1
#   PGBACKREST_PG_PATH        default /var/lib/postgresql/data
#   WAL_ARCHIVE_PROVIDER      s3 | gcs | none (default s3)
#   WAL_ARCHIVE_BUCKET        bucket holding the WAL archive
#   WAL_ARCHIVE_PREFIX        default tessera/archive
#   PAGERDUTY_ROUTING_KEY     optional Events API v2 routing key
#   KEEP_STANDBY              true → leave the standby running after the drill
#   DRY_RUN                   1|true → print the plan, change nothing
#
# Exit codes: 0 pass, 1 failure, 2 warning (drill completed but RTO/RPO
# exceeded a target or an assertion was inconclusive).
# =============================================================================

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly RUN_ID="drill-$(date -u +%Y%m%dT%H%M%SZ)"
readonly START_EPOCH="$(date +%s)"
readonly RESULTS_DIR="${DR_RESULTS_DIR:-${SCRIPT_DIR}/drill-results}"
readonly REPORT_JSON="${DR_REPORT_PATH:-${RESULTS_DIR}/${RUN_ID}.json}"

DR_MODE="${DR_MODE:-pgbackrest}"
DRY_RUN="${DRY_RUN:-false}"
KEEP_STANDBY="${KEEP_STANDBY:-false}"

RTO_TARGET_SECONDS="${RTO_TARGET_SECONDS:-900}"
RPO_TARGET_SECONDS="${RPO_TARGET_SECONDS:-300}"

STANDBY_TERRAFORM_DIR="${STANDBY_TERRAFORM_DIR:-${SCRIPT_DIR}/../terraform/environments/prod}"
STANDBY_TERRAFORM_TARGET="${STANDBY_TERRAFORM_TARGET:-module.warm_standby}"
STANDBY_API_URL="${STANDBY_API_URL:-}"
API_TEST_CMD="${API_TEST_CMD:-}"

PGBACKREST_STANZA="${PGBACKREST_STANZA:-tessera}"
PGBACKREST_CONFIG="${PGBACKREST_CONFIG:-/etc/pgbackrest/pgbackrest.conf}"
PGBACKREST_REPO="${PGBACKREST_REPO:-repo1}"
PGBACKREST_PG_PATH="${PGBACKREST_PG_PATH:-/var/lib/postgresql/data}"

WAL_ARCHIVE_PROVIDER="${WAL_ARCHIVE_PROVIDER:-s3}"
WAL_ARCHIVE_BUCKET="${WAL_ARCHIVE_BUCKET:-}"
WAL_ARCHIVE_PREFIX="${WAL_ARCHIVE_PREFIX:-tessera/archive}"
PAGERDUTY_ROUTING_KEY="${PAGERDUTY_ROUTING_KEY:-}"

WARNINGS=0
ERRORS=0
STANDBY_UP=false
REPORT_WRITTEN=false
RPO_SECONDS=""
RTO_SECONDS=""
STANDBY_HEALTHY=false

log() {
  local level="$1"; shift
  printf '[%s] [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${level}" "$*" >&2
}

warn() { WARNINGS=$((WARNINGS + 1)); log WARN "$*"; }
fail() { ERRORS=$((ERRORS + 1)); log ERROR "$*"; }
step() { log INFO "── $* ──"; }

is_dry_run() { [[ "${DRY_RUN}" == "true" || "${DRY_RUN}" == "1" ]]; }

# ---------------------------------------------------------------------------
# Legacy snapshot mode: keep the daily logical-restore pipeline available.
# ---------------------------------------------------------------------------
if [[ "${DR_MODE}" == "snapshot" ]]; then
  exec "${SCRIPT_DIR}/../scripts/dr_test.sh" "$@"
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight() {
  step "Preflight"
  local missing=()
  for cmd in jq curl pgbackrest terraform; do
    command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
  done
  if [[ "${WAL_ARCHIVE_PROVIDER}" == "s3" ]]; then
    command -v aws >/dev/null 2>&1 || missing+=("aws")
  elif [[ "${WAL_ARCHIVE_PROVIDER}" == "gcs" ]]; then
    command -v gsutil >/dev/null 2>&1 || missing+=("gsutil")
  fi
  if ((${#missing[@]} > 0)); then
    fail "missing required tools: ${missing[*]}"
    return 1
  fi

  [[ -d "${STANDBY_TERRAFORM_DIR}" ]] || { fail "STANDBY_TERRAFORM_DIR not found: ${STANDBY_TERRAFORM_DIR}"; return 1; }
  [[ -f "${PGBACKREST_CONFIG}" ]] || warn "pgBackRest config not found at ${PGBACKREST_CONFIG}; restore will rely on the ambient default"
  mkdir -p "${RESULTS_DIR}"
  if [[ -z "${STANDBY_API_URL}" ]]; then
    warn "STANDBY_API_URL is unset; RTO stops at standby creation and the API checks are skipped"
  fi
}

# ---------------------------------------------------------------------------
# RPO measurement: age of the newest archived WAL segment
# ---------------------------------------------------------------------------
newest_wal_timestamp() {
  case "${WAL_ARCHIVE_PROVIDER}" in
    s3)
      [[ -n "${WAL_ARCHIVE_BUCKET}" ]] || return 1
      aws s3api list-objects-v2 \
        --bucket "${WAL_ARCHIVE_BUCKET}" \
        --prefix "${WAL_ARCHIVE_PREFIX}/" \
        --query 'sort_by(Contents,&LastModified)[-1].LastModified' \
        --output text 2>/dev/null
      ;;
    gcs)
      [[ -n "${WAL_ARCHIVE_BUCKET}" ]] || return 1
      gsutil ls -l "gs://${WAL_ARCHIVE_BUCKET}/${WAL_ARCHIVE_PREFIX}/**" 2>/dev/null \
        | awk '$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]{4}-/ {print $2"T"$3"Z"}' \
        | sort | tail -1
      ;;
    none)
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

measure_rpo() {
  step "Measure RPO"
  local newest
  if ! newest="$(newest_wal_timestamp)" || [[ -z "${newest}" || "${newest}" == "None" ]]; then
    warn "could not determine the newest archived WAL segment (provider=${WAL_ARCHIVE_PROVIDER})"
    RPO_SECONDS=""
    return 0
  fi
  local newest_epoch
  if newest_epoch="$(date -u -d "${newest}" +%s 2>/dev/null)"; then
    :
  else
    warn "unparseable WAL archive timestamp: ${newest}"
    RPO_SECONDS=""
    return 0
  fi
  RPO_SECONDS=$(( $(date +%s) - newest_epoch ))
  log INFO "newest archived WAL: ${newest} → RPO ${RPO_SECONDS}s (target ${RPO_TARGET_SECONDS}s)"
  if (( RPO_SECONDS > RPO_TARGET_SECONDS )); then
    warn "RPO ${RPO_SECONDS}s exceeds the ${RPO_TARGET_SECONDS}s target"
  fi
}

# ---------------------------------------------------------------------------
# Warm standby lifecycle
# ---------------------------------------------------------------------------
terraform_standby() {
  local action="$1"
  if is_dry_run; then
    log INFO "[dry-run] terraform ${action} in ${STANDBY_TERRAFORM_DIR} (target ${STANDBY_TERRAFORM_TARGET})"
    return 0
  fi
  terraform -chdir="${STANDBY_TERRAFORM_DIR}" "${action}" -auto-approve -input=false \
    -var 'enable_warm_standby=true' \
    ${STANDBY_TERRAFORM_TARGET:+-target="${STANDBY_TERRAFORM_TARGET}"} \
    ${TERRAFORM_EXTRA_ARGS:-}
}

standby_up() {
  step "Spin up warm standby"
  terraform_standby apply
  STANDBY_UP=true
}

standby_down() {
  if [[ "${STANDBY_UP}" != "true" || "${KEEP_STANDBY}" == "true" ]]; then
    return 0
  fi
  step "Tear down warm standby"
  terraform_standby destroy || warn "standby teardown failed; verify the ECS service manually"
}

# ---------------------------------------------------------------------------
# Restore the latest backup + WAL
# ---------------------------------------------------------------------------
restore_standby() {
  step "Restore latest backup and WAL"
  if is_dry_run; then
    log INFO "[dry-run] pgbackrest --stanza=${PGBACKREST_STANZA} --repo=${PGBACKREST_REPO} restore --delta --type=immediate"
    return 0
  fi
  # `--type=immediate` replays every archived segment and leaves the standby
  # ready to promote, which is what the RTO measurement should include.
  pgbackrest --config="${PGBACKREST_CONFIG}" \
    --stanza="${PGBACKREST_STANZA}" \
    --repo="${PGBACKREST_REPO}" \
    --pg1-path="${PGBACKREST_PG_PATH}" \
    restore --delta --type=immediate --target-action=promote
  pgbackrest --config="${PGBACKREST_CONFIG}" --stanza="${PGBACKREST_STANZA}" check
}

# ---------------------------------------------------------------------------
# API health + read-only assertions
# ---------------------------------------------------------------------------
wait_for_api() {
  [[ -n "${STANDBY_API_URL}" ]] || return 0
  step "Wait for standby API"
  local deadline=$(( START_EPOCH + RTO_TARGET_SECONDS + 300 ))
  while (( $(date +%s) < deadline )); do
    if curl -fsS --max-time 5 "${STANDBY_API_URL%/}/health" >/dev/null 2>&1; then
      STANDBY_HEALTHY=true
      return 0
    fi
    sleep 5
  done
  fail "standby API did not become healthy before the drill deadline"
  return 1
}

run_api_tests() {
  [[ "${STANDBY_HEALTHY}" == "true" ]] || return 0
  step "API test suite (read-only)"
  if is_dry_run; then
    log INFO "[dry-run] would run: ${API_TEST_CMD:-health, stats and assets assertions}"
    return 0
  fi

  local base="${STANDBY_API_URL%/}"
  for path in /health /stats /assets; do
    if curl -fsS --max-time 10 "${base}${path}" >/dev/null; then
      log INFO "GET ${path} OK"
    else
      fail "GET ${path} failed against the standby"
    fi
  done

  # The standby must be read-only: a write must never be accepted.
  local status
  status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "${base}/v1/admin/dlq/retry" || true)"
  if [[ "${status}" == "2"* ]]; then
    fail "standby accepted a write (HTTP ${status}); it is not read-only"
  else
    log INFO "write rejected as expected (HTTP ${status})"
  fi

  if [[ -n "${API_TEST_CMD}" ]]; then
    log INFO "running API_TEST_CMD: ${API_TEST_CMD}"
    if ! bash -c "${API_TEST_CMD}"; then
      fail "API_TEST_CMD failed"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
to_seconds_or_null() {
  if [[ -n "$1" ]]; then printf '%s' "$1"; else printf 'null'; fi
}

write_report() {
  local exit_code="$1"
  local now; now="$(date +%s)"
  RTO_SECONDS=$(( now - START_EPOCH ))
  local rto_within="null" rpo_within="null"
  (( RTO_SECONDS <= RTO_TARGET_SECONDS )) && rto_within="true" || rto_within="false"
  if [[ -n "${RPO_SECONDS}" ]]; then
    (( RPO_SECONDS <= RPO_TARGET_SECONDS )) && rpo_within="true" || rpo_within="false"
  fi

  local result="success"
  [[ "${exit_code}" -eq 2 || "${WARNINGS}" -gt 0 ]] && result="warning"
  [[ "${exit_code}" -eq 1 || "${ERRORS}" -gt 0 ]] && result="failure"

  mkdir -p "$(dirname "${REPORT_JSON}")"
  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg mode "${DR_MODE}" \
    --arg result "${result}" \
    --argjson rto_seconds "$(to_seconds_or_null "${RTO_SECONDS}")" \
    --argjson rpo_seconds "$(to_seconds_or_null "${RPO_SECONDS}")" \
    --argjson rto_target "${RTO_TARGET_SECONDS}" \
    --argjson rpo_target "${RPO_TARGET_SECONDS}" \
    --argjson rto_within "$rto_within" \
    --argjson rpo_within "$rpo_within" \
    --argjson warnings "${WARNINGS}" \
    --argjson errors "${ERRORS}" \
    --arg stanza "${PGBACKREST_STANZA}" \
    --arg repo "${PGBACKREST_REPO}" \
    --arg started "$(date -u -d "@${START_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)" \
    --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      run_id: $run_id,
      mode: $mode,
      result: $result,
      started_utc: $started,
      finished_utc: $finished,
      rto: { measured_seconds: $rto_seconds, target_seconds: $rto_target, within_target: $rto_within },
      rpo: { measured_seconds: $rpo_seconds, target_seconds: $rpo_target, within_target: $rpo_within },
      backup: { stanza: $stanza, repo: $repo },
      warnings: $warnings,
      errors: $errors
    }' > "${REPORT_JSON}"
  REPORT_WRITTEN=true
  log INFO "drill report: ${REPORT_JSON}"
}

append_summary() {
  local summary="${RESULTS_DIR}/SUMMARY.md"
  local result
  result="$(jq -r '.result' "${REPORT_JSON}" 2>/dev/null || echo unknown)"
  [[ -f "${summary}" ]] || printf '# DR drill results\n\n| Run | Result | RTO (s) | RPO (s) |\n| --- | --- | --- | --- |\n' > "${summary}"
  printf '| %s | %s | %s | %s |\n' \
    "${RUN_ID}" "${result}" "${RTO_SECONDS:-unknown}" "${RPO_SECONDS:-unknown}" >> "${summary}"
}

pagerduty_report() {
  [[ -n "${PAGERDUTY_ROUTING_KEY}" ]] || return 0
  local result
  result="$(jq -r '.result' "${REPORT_JSON}" 2>/dev/null || echo failure)"
  local event_action="resolve" severity="info"
  if [[ "${result}" != "success" ]]; then
    event_action="trigger"
    severity="$([[ "${result}" == "failure" ]] && echo critical || echo warning)"
  fi
  curl -fsS -X POST "https://events.pagerduty.com/v2/enqueue" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n \
      --arg key "${PAGERDUTY_ROUTING_KEY}" \
      --arg action "${event_action}" \
      --arg severity "${severity}" \
      --arg run_id "${RUN_ID}" \
      --argjson rto "${RTO_SECONDS:-0}" \
      --argjson rpo "${RPO_SECONDS:-0}" \
      '{
        routing_key: $key,
        event_action: $action,
        dedup_key: ("tessera-dr-drill-" + $run_id),
        payload: {
          summary: ("Tessera weekly DR drill: " + $run_id),
          severity: $severity,
          source: "restore_verification.sh",
          custom_details: { rto_seconds: $rto, rpo_seconds: $rpo }
        }
      }')" >/dev/null || warn "PagerDuty notification failed"
}

cleanup() {
  local exit_code=$?
  standby_down
  if [[ "${REPORT_WRITTEN}" != "true" ]]; then
    write_report "${exit_code}"
  fi
  append_summary
  pagerduty_report
  exit "${exit_code}"
}
trap cleanup EXIT

main() {
  log INFO "Tessera DR drill ${RUN_ID} (mode=${DR_MODE}, dry-run=${DRY_RUN})"
  preflight
  measure_rpo
  standby_up
  restore_standby
  wait_for_api
  run_api_tests

  local exit_code=0
  (( ERRORS > 0 )) && exit_code=1
  if (( exit_code == 0 )); then
    RTO_SECONDS=$(( $(date +%s) - START_EPOCH ))
    if (( RTO_SECONDS > RTO_TARGET_SECONDS )); then
      warn "RTO ${RTO_SECONDS}s exceeds the ${RTO_TARGET_SECONDS}s target"
      exit_code=2
    fi
    if [[ -n "${RPO_SECONDS}" ]] && (( RPO_SECONDS > RPO_TARGET_SECONDS )); then
      exit_code=2
    fi
  fi
  log INFO "drill finished in $(( $(date +%s) - START_EPOCH ))s"
  return "${exit_code}"
}

main "$@"
