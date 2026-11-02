#!/bin/bash
# Runs the mock driver (serve.py) and the agent side by side. Both log to the
# container's stdout, prefixed, and to /data/logs. Stops when either exits.
set -u
: "${NX_BOOTSTRAP:?set NX_BOOTSTRAP in mock/sim/docker/.env}"
mkdir -p /data/agent /data/logs

python3 /opt/zfsim/scripts/serve.py \
  > >(tee -a /data/logs/sim.log | sed -u 's/^/[sim]   /') 2>&1 &
SIM=$!

/opt/nexufend/nexufend-agent \
  --bootstrap-data "$NX_BOOTSTRAP" \
  --bin-dir /opt/nexufend --data-dir /data/agent \
  --log-stdout --log "${NX_LOG:-debug}" --devmode \
  > >(tee -a /data/logs/agent.log | sed -u 's/^/[agent] /') 2>&1 &
AGENT=$!

trap 'kill -TERM $AGENT $SIM 2>/dev/null; wait $AGENT; kill -TERM $SIM 2>/dev/null' TERM INT
wait -n $SIM $AGENT
status=$?
kill -TERM $AGENT $SIM 2>/dev/null
wait
exit $status
