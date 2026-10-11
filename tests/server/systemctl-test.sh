#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

set -euo pipefail
unit=vos-lifecycle.service
cleanup(){
  systemctl stop "$unit" || true
  rm -f "/etc/systemd/system/$unit" "/tmp/$unit.log" /tmp/lifecycle.py /tmp/lifecycle-start.log /tmp/lifecycle-stopped-*
}
trap cleanup EXIT
cat > /tmp/lifecycle.py <<'PY'
import os
import signal
import socket
import time


def stop(*_):
    time.sleep(0.7)
    open(f'/tmp/lifecycle-stopped-{os.getpid()}', 'w').close()
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
time.sleep(0.4)
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 14442))
    listener.listen()
    while True:
        signal.pause()
PY
printf 'ExecStart=/usr/bin/python3 /tmp/lifecycle.py\n' > "/etc/systemd/system/$unit"

# Startup and restart must wait for the service, even beyond the old fixed sleeps.
systemctl start "$unit"
old_pid=$(systemctl show "$unit" -p MainPID --value)
[[ $(ss -H -ltnp 'sport = :14442') == *"pid=$old_pid,"* ]]
systemctl restart "$unit"
pid=$(systemctl show "$unit" -p MainPID --value)
[[ $pid != "$old_pid" && -f /tmp/lifecycle-stopped-$old_pid ]]
[[ $(ss -H -ltnp 'sport = :14442') == *"pid=$pid,"* ]]
systemctl stop "$unit"
[[ -f /tmp/lifecycle-stopped-$pid && -z $(ss -H -ltn 'sport = :14442') ]]

# An exited (possibly unreaped) PID must not count as an active service.
echo "$pid" > "/tmp/test-units/$unit.pid"
if systemctl is-active --quiet "$unit"; then
  echo 'exited service reported active' >&2; exit 1
else
  [[ $? == 3 ]]
fi
rm "/tmp/test-units/$unit.pid"

printf 'ExecStart=/bin/false\n' > "/etc/systemd/system/$unit"
if systemctl start "$unit" 2>/tmp/lifecycle-start.log; then
  echo 'failed service reported started' >&2; exit 1
else
  [[ $? == 1 ]]
fi
[[ ! -f /tmp/test-units/$unit.pid ]]
echo 'PASS: service shim waits for startup/shutdown and rejects exited services'
