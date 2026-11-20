#!/bin/sh
# Brings up a local enterprise stack: control plane (development sign-in), gateway, and a mock
# Anthropic API that answers without spending money. Prints the environment for `vp run dev`.
#
#   enterprise/dev/demo.sh <state-dir>          start everything
#   enterprise/dev/demo.sh <state-dir> stop     stop what this script started
set -eu

DIR=${1:?usage: demo.sh <state-dir> [stop]}
mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

if [ "${2:-}" = "stop" ]; then
  for name in gateway control-plane mock; do
    if [ -f "$DIR/$name.pid" ]; then
      kill "$(cat "$DIR/$name.pid")" 2>/dev/null || true
      rm -f "$DIR/$name.pid"
    fi
  done
  echo "Stopped."
  exit 0
fi

CP="$ROOT/enterprise/control-plane/src/bin.ts"
if [ ! -f "$DIR/cp/control-plane.json" ]; then
  node "$CP" init --dir "$DIR/cp" --organization "Example Corp" >/dev/null
fi
set -a
. "$DIR/cp/secrets.env"
set +a
if [ ! -f "$DIR/gw/tls.crt" ]; then
  node "$CP" server-cert --config "$DIR/cp/control-plane.json" --host localhost --host 127.0.0.1 --out "$DIR/gw" >/dev/null
fi

cat >"$DIR/gw/gateway.json" <<EOF
{
  "listen": { "host": "127.0.0.1", "port": 9443 },
  "tls": { "certPath": "tls.crt", "keyPath": "tls.key" },
  "deviceCaPath": "$DIR/cp/data/ca.crt",
  "controlPlaneUrl": "https://localhost:8443",
  "controlPlaneCaPath": "$DIR/cp/data/ca.crt",
  "syncIntervalSeconds": 5,
  "upstreams": [{ "family": "anthropic", "baseUrl": "http://127.0.0.1:8790", "apiKeyEnv": "DEMO_ANTHROPIC_KEY" }]
}
EOF

export DEMO_ANTHROPIC_KEY=sk-demo-org-key-held-by-gateway
node "$ROOT/enterprise/dev/mock-anthropic.mjs" 8790 "$DIR/mock-anthropic.log" >"$DIR/mock.out" 2>&1 &
echo $! >"$DIR/mock.pid"
node "$CP" serve --config "$DIR/cp/control-plane.json" >"$DIR/control-plane.out" 2>&1 &
echo $! >"$DIR/control-plane.pid"
i=0
until curl -sf --cacert "$DIR/cp/data/ca.crt" https://localhost:8443/healthz >/dev/null 2>&1; do
  i=$((i + 1))
  [ $i -gt 50 ] && { echo "Control plane did not start; see $DIR/control-plane.out"; exit 1; }
  sleep 0.2
done
node "$ROOT/enterprise/gateway/src/bin.ts" --config "$DIR/gw/gateway.json" >"$DIR/gateway.out" 2>&1 &
echo $! >"$DIR/gateway.pid"

curl -sf --cacert "$DIR/cp/data/ca.crt" -X PUT https://localhost:8443/v1/admin/policy \
  -H "authorization: Bearer $T3E_ADMIN_API_TOKEN" -H 'content-type: application/json' \
  -d '{"document":{"schemaVersion":1,"organization":"Example Corp","limits":{"connect":false,"telemetry":false,"maxRuntimeMode":"auto-accept-edits","providers":{"allowedDrivers":["claudeAgent"]}}}}' >/dev/null

node "$CP" trust --config "$DIR/cp/control-plane.json" >"$DIR/trust.json"
node -e '
const fs = require("node:fs");
const trust = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
fs.writeFileSync(process.argv[2], JSON.stringify({
  schemaVersion: 1,
  organization: trust.organization,
  controlPlaneUrl: trust.controlPlaneUrl,
  gatewayUrl: "https://localhost:9443",
  policyKeys: trust.policyKeys,
  serverCaPem: trust.caPem,
  bootstrapPolicy: { schemaVersion: 1, organization: trust.organization, limits: { connect: false, maxRuntimeMode: "approval-required", providers: { allowedDrivers: ["claudeAgent"] } } },
  policyRefreshSeconds: 60,
}, null, 2) + "\n");
' "$DIR/trust.json" "$DIR/enterprise.json"

cat <<EOF
Running: control plane https://localhost:8443 (admin: /admin), gateway https://localhost:9443,
mock Anthropic on 127.0.0.1:8790. Logs and state are in $DIR.

Point a T3 dev server at it:
  export T3CODE_DEV_ENTERPRISE_CONFIG_PATH=$DIR/enterprise.json
  export T3CODE_ENTERPRISE_STATE_DIR=$DIR/device
  node apps/server/src/bin.ts enterprise enroll     # sign in with any email
  vp run dev

Admin API token: $DIR/cp/secrets.env (T3E_ADMIN_API_TOKEN). Stop with: $0 $DIR stop
EOF
