#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

set -euo pipefail
shellcheck /install.sh
ssh-keygen -q -t ed25519 -N '' -f /tmp/client
args=(--binary /vos --user vos-test --create-user --public-key /tmp/client.pub --port 14443)
bash /install.sh "${args[@]}"
/usr/sbin/sshd -t -f /etc/vos/sshd_config
systemd-analyze verify /etc/systemd/system/vos-sshd.service /etc/systemd/system/vos-relay.service
effective=$(/usr/sbin/sshd -T -f /etc/vos/sshd_config)
for value in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'allowtcpforwarding local' 'maxsessions 0' 'permittty no' 'permitrootlogin no'; do
  grep -qx "$value" <<< "$effective"
done
[[ $(ss -H -ltn 'sport = :10819') == *'127.0.0.1:10819'* ]]
# Real OpenSSH public-key login + SSH-forwarded TCP and UDP via the installed relay.
cat /etc/ssh/ssh_host_ed25519_key.pub > /tmp/host.pub
/vos init --config /tmp/client.json --server 127.0.0.1 --port 14443 --user vos-test --identity /tmp/client --host-key-file /tmp/host.pub
/vos validate --config /tmp/client.json
# Disable localhost bypass for the remote relay test using a small text substitution.
sed -i 's/"bypass_private": true/"bypass_private": false/;s/"bypass_ru": true/"bypass_ru": false/' /tmp/client.json
/vos run --config /tmp/client.json >/tmp/client.log 2>&1 & client_pid=$!
trap 'kill "$client_pid" 2>/dev/null || true' EXIT
sleep 0.3
python3 /fixtures.py >/tmp/fixtures.log 2>&1 & fixture_pid=$!
trap 'kill "$client_pid" "$fixture_pid" 2>/dev/null || true' EXIT
sleep 0.2
/vos probe --url http://127.0.0.1:18080 --dns 127.0.0.1:15353
# Idempotent upgrade, then a failed upgrade must restore the old port and services.
bash /install.sh "${args[@]}"
before=$(sha256sum /etc/vos/sshd_config /etc/vos/relay.json /usr/local/lib/vos/vos)
touch /tmp/fail-once
if bash /install.sh "${args[@]}" --port 14444; then echo 'failure injection unexpectedly succeeded' >&2; exit 1; fi
[[ $before == "$(sha256sum /etc/vos/sshd_config /etc/vos/relay.json /usr/local/lib/vos/vos)" ]]
systemctl is-active --quiet vos-sshd.service
systemctl is-active --quiet vos-relay.service
[[ -n $(ss -H -ltn 'sport = :14443') && -z $(ss -H -ltn 'sport = :14444') ]]
# --reuse-ssh must leave the SSH config and active process untouched.
ssh_pid=$(systemctl show vos-sshd.service -p MainPID --value)
bash /install.sh --binary /vos --reuse-ssh --port 14443
[[ $ssh_pid == "$(systemctl show vos-sshd.service -p MainPID --value)" ]]
[[ $before == "$(sha256sum /etc/vos/sshd_config /etc/vos/relay.json /usr/local/lib/vos/vos)" ]]
echo 'PASS: real OpenSSH + relay TCP/UDP; idempotent install; rollback; reuse; config hardening'
