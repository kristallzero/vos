#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

# Optional Linux TUN lifecycle check. Requires NET_ADMIN and /dev/net/tun.
set -euo pipefail
bash /test.sh
python3 - <<'PY'
import json
c = json.load(open('/tmp/client.json'))
c['mode'] = 'tun'
c['tun']['name'] = 'vos-smoke'
c['ssh']['interface'] = 'lo'
json.dump(c, open('/tmp/tun.json', 'w'))
PY
/vos run --config /tmp/tun.json >/tmp/tun.log 2>&1 & pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for _ in {1..40}; do
  if ip link show vos-smoke >/dev/null 2>&1 && grep -q 'started in tun mode' /tmp/tun.log; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then cat /tmp/tun.log; exit 1; fi
  sleep 0.1
done
ip -4 addr show dev vos-smoke | grep -q '172.31.255.1/30'
ip -6 addr show dev vos-smoke | grep -q 'fdfe:dcba:9876::1/126'
ip rule show | grep -q '2022'
kill -TERM "$pid"
wait "$pid"
if ip link show vos-smoke >/dev/null 2>&1 || ip rule show | grep -q '2022'; then echo 'TUN cleanup failed'; exit 1; fi
echo 'PASS: Linux TUN start, dual-stack addresses, auto routes, SIGTERM cleanup'
