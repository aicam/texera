#!/usr/bin/env bash
# End-to-end cache test for workflow 8 ("Test cache") on the live EKS deployment.
#
# Runs the workflow twice via the CU pod's SyncExecutionResource:
#   pass 1 -> populates operator_port_cache
#   pass 2 -> should hit cache (operators COMPLETED_FROM_CACHE, numWorkers=0)
#
# The session JWT is minted from the cluster's OWN deployed AUTH_JWT_SECRET at
# runtime (never hardcoded here) and authenticates as the deployment owner
# (uid 2), exactly as documented in the eks-knowledge-base skill. Review before
# running. Requires: kubectl context admin@dknet.us-west-1.eksctl.io, python3+PyJWT.
set -euo pipefail
CTX=admin@dknet.us-west-1.eksctl.io
NS=default
POOL_NS=texera-workflow-computing-unit-pool
WID=8

echo "==> 1. Find a running computing unit owned by uid=2"
CUID=$(kubectl --context "$CTX" exec -n "$NS" texera-postgresql-0 -- bash -c \
  'PGPASSWORD=$POSTGRES_PASSWORD psql -U postgres -d texera_db -tAc \
   "SELECT cuid FROM texera_db.workflow_computing_unit WHERE uid=2 AND terminate_time IS NULL ORDER BY cuid DESC LIMIT 1;"' | tr -d '[:space:]')
if [ -z "$CUID" ]; then
  echo "No active CU for uid=2. Create one in the UI (or via the CU manager API) first, then re-run."
  exit 1
fi
echo "    using CUID=$CUID"
CU_POD="computing-unit-$CUID"
kubectl --context "$CTX" get pod "$CU_POD" -n "$POOL_NS" -o jsonpath='    pod image={.spec.containers[0].image}{"\n"}'

echo "==> 2. Mint session JWT from cluster AUTH_JWT_SECRET (runtime, not stored)"
SECRET=$(kubectl --context "$CTX" get deploy texera-webserver -n "$NS" \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' \
  | awk -F= '/^AUTH_JWT_SECRET=/{print $2}')
TOKEN=$(AUTH_JWT_SECRET="$SECRET" python3 /tmp/forge_jwt.py)

echo "==> 3. Build SyncExecutionRequest from workflow 8 content (target op8 = Sort)"
kubectl --context "$CTX" exec -n "$NS" texera-postgresql-0 -- bash -c \
  'PGPASSWORD=$POSTGRES_PASSWORD psql -U postgres -d texera_db -tAc "SELECT content FROM texera_db.workflow WHERE wid=8;"' \
  > /tmp/wf8_content.json
python3 /tmp/build_sync_req.py /tmp/wf8_content.json "cache-test" op8 > /tmp/wf8_req.json
echo "    request bytes: $(wc -c < /tmp/wf8_req.json)"

run_pass() {
  local label="$1"
  echo "==> $label: POST /api/execution/$WID/$CUID/run"
  kubectl --context "$CTX" cp /tmp/wf8_req.json "$NS/$(kubectl --context $CTX get pod -n $NS -l app=texera-webserver -o jsonpath='{.items[0].metadata.name}'):/tmp/wf8_req.json"
  kubectl --context "$CTX" exec -n "$NS" deploy/texera-webserver -- \
    curl -s -X POST -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" -H "Accept: application/json" \
      --data @/tmp/wf8_req.json \
      "http://$CU_POD.texera-workflow-computing-unit-svc.$POOL_NS.svc.cluster.local:8085/api/execution/$WID/$CUID/run" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("    success=",d.get("success"),"state=",d.get("state")); [print("    op",k,"state=",v.get("state"),"in=",v.get("inputTuples"),"out=",v.get("outputTuples")) for k,v in (d.get("operators") or {}).items()]'
}

show_cache_rows() {
  echo "    operator_port_cache rows for wid=8:"
  kubectl --context "$CTX" exec -n "$NS" texera-postgresql-0 -- bash -c \
   'PGPASSWORD=$POSTGRES_PASSWORD psql -U postgres -d texera_db -c "SELECT global_port_id, left(subdag_hash,12) AS hash, tuple_count, source_execution_id FROM texera_db.operator_port_cache WHERE workflow_id=8 ORDER BY updated_at;"'
}

run_pass "PASS 1 (cold — populates cache)"
show_cache_rows
echo "==> waiting 5s for async cache upsert..."; sleep 5
show_cache_rows
run_pass "PASS 2 (warm — expect COMPLETED_FROM_CACHE)"
echo "==> Done. In PASS 2, cached operators should report from-cache completion."
