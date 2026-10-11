#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

# VoS server installer: Debian/Ubuntu with systemd. Never changes the admin ssh unit.
set -Eeuo pipefail
umask 077
SSH_USER="" SSH_PORT=443 RELAY_PORT=10819 PUBLIC_KEY="" BINARY=""
REUSE_SSH=0 CREATE_USER=0 PRINT_SSH=0 PRINT_RELAY=0 OPEN_FIREWALL=0
BASE=/etc/vos
BIN=/usr/local/lib/vos/vos
MARKER="$BASE/.managed"
SSH_UNIT=/etc/systemd/system/vos-sshd.service
RELAY_UNIT=/etc/systemd/system/vos-relay.service
MANAGED='Managed by VoS installer v1'
die(){ echo "VoS: $*" >&2; exit 1; }
usage(){ cat <<'EOF'
Usage: sudo bash install.sh --binary ./vos-linux-amd64 [--reuse-ssh]
       --user USER --public-key client.pub [--create-user] [--port 443]
Options:
  --reuse-ssh             Preserve an existing SSH listener; install only relay
  --relay-port PORT      Loopback relay TCP port (10819)
  --open-firewall        Allow SSH TCP port in active UFW (dedicated mode only)
  --print-config        Render dedicated sshd config without installing
  --print-relay-config  Render relay config without installing
The client PRIVATE key stays on the client. --public-key is an authorized .pub key.
EOF
}
need_value(){ [[ $# -ge 2 && -n $2 ]] || die "missing value for $1"; }
while (($#)); do
  case "$1" in
    --user) need_value "$@"; SSH_USER=$2; shift 2;;
    --port) need_value "$@"; SSH_PORT=$2; shift 2;;
    --relay-port) need_value "$@"; RELAY_PORT=$2; shift 2;;
    --public-key) need_value "$@"; PUBLIC_KEY=$2; shift 2;;
    --binary) need_value "$@"; BINARY=$2; shift 2;;
    --reuse-ssh) REUSE_SSH=1; shift;;
    --create-user) CREATE_USER=1; shift;;
    --open-firewall) OPEN_FIREWALL=1; shift;;
    --print-config) PRINT_SSH=1; shift;;
    --print-relay-config) PRINT_RELAY=1; shift;;
    --help|-h) usage; exit 0;;
    *) die "unknown option: $1";;
  esac
done
valid_port(){ [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 > 0 && 10#$1 <= 65535)); }
if ! valid_port "$SSH_PORT" || ! valid_port "$RELAY_PORT"; then die "invalid port"; fi
SSH_PORT=$((10#$SSH_PORT)); RELAY_PORT=$((10#$RELAY_PORT))
[[ -z $SSH_USER || $SSH_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid user name"
render_ssh(){
  [[ -n $SSH_USER ]] || die "--user is required"
  cat <<EOF
# $MANAGED
Port $SSH_PORT
ListenAddress 0.0.0.0
ListenAddress ::
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/vos-sshd.pid
UsePAM yes
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers $SSH_USER
AuthorizedKeysFile $BASE/authorized_keys/%u
StrictModes yes
AllowTcpForwarding local
PermitOpen any
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
MaxSessions 0
ForceCommand /bin/false
ClientAliveInterval 15
ClientAliveCountMax 3
LogLevel VERBOSE
EOF
}
render_relay(){ cat <<EOF
{"version":1,"listen":"127.0.0.1","port":$RELAY_PORT,"log_level":"info","dns":"1.1.1.1"}
EOF
}
if ((PRINT_SSH)); then render_ssh; exit 0; fi
if ((PRINT_RELAY)); then render_relay; exit 0; fi
((EUID==0)) || die "run as root"
[[ -f /etc/debian_version && -d /run/systemd/system ]] || die "requires Debian/Ubuntu running systemd"
[[ -n $BINARY && -f $BINARY && -x $BINARY ]] || die "--binary must be an executable Linux VoS build"
"$BINARY" version | head -n 1 | grep -q '^VoS ' || die "invalid VoS binary or incompatible architecture"
if ((!REUSE_SSH)); then
  [[ -n $SSH_USER && $SSH_USER != root ]] || die "a non-root --user is required"
  [[ -f $PUBLIC_KEY ]] || die "--public-key must point to a client .pub file"
fi
if [[ -d $BASE || -e $SSH_UNIT || -e $RELAY_UNIT || -e $BIN ]]; then
  [[ -f $MARKER && $(cat "$MARKER") == "$MANAGED" ]] || die "refusing to replace files without VoS ownership marker"
fi
command -v flock >/dev/null || die "flock from util-linux is required"
exec 9>/run/vos-install.lock
flock -n 9 || die "another installer is running"
export DEBIAN_FRONTEND=noninteractive
if ! command -v /usr/sbin/sshd >/dev/null || ! command -v ss >/dev/null; then
  apt-get update
  apt-get install -y openssh-server iproute2
fi
install -d -m 0755 /run/sshd
ssh-keygen -A
if ((!REUSE_SSH)); then
  [[ $(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$PUBLIC_KEY") == 1 ]] || die "public-key must contain exactly one key"
  ssh-keygen -lf "$PUBLIC_KEY" >/dev/null || die "invalid public key"
  [[ $(awk 'NF && $1 !~ /^#/ {print $1}' "$PUBLIC_KEY") =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-) ]] || die "only plain authorized public keys are supported"
  if ! id "$SSH_USER" >/dev/null 2>&1; then
    ((CREATE_USER)) || die "user does not exist; use --create-user"
    useradd --create-home --shell /usr/sbin/nologin "$SSH_USER"
  fi
fi
if id vos-relay >/dev/null 2>&1; then
  [[ $(getent passwd vos-relay | cut -d: -f7) == /usr/sbin/nologin ]] || die "existing vos-relay account is not the expected service account"
else
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vos-relay
fi
port_owner_check(){
  local port=$1 unit=$2 listeners pid
  listeners=$(ss -H -ltnp "sport = :$port")
  [[ -z $listeners ]] && return 0
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  [[ -f $MARKER && $pid =~ ^[1-9][0-9]*$ ]] || die "TCP port $port is occupied by another service"
  while IFS= read -r line; do [[ $line == *"pid=$pid,"* ]] || die "TCP port $port is occupied by another service"; done <<< "$listeners"
}
port_owner_check "$RELAY_PORT" vos-relay.service
if ((REUSE_SSH)); then
  [[ -n $(ss -H -ltn "sport = :$SSH_PORT") ]] || die "--reuse-ssh requires an existing listener on TCP $SSH_PORT"
else
  port_owner_check "$SSH_PORT" vos-sshd.service
fi
STAGE=$(mktemp -d /tmp/vos-install.XXXXXX)
CHANGED=0 FIREWALL_ADDED=0
declare -a FILES=() EXISTED=()
declare -A WAS_ACTIVE=() WAS_ENABLED=()
UNITS=(vos-relay.service)
if ((!REUSE_SSH)); then UNITS+=(vos-sshd.service); fi
for unit in "${UNITS[@]}"; do
  WAS_ACTIVE[$unit]=$(systemctl is-active "$unit" 2>/dev/null || true)
  WAS_ENABLED[$unit]=$(systemctl is-enabled "$unit" 2>/dev/null || true)
done
backup(){ local dest=$1 n=${#FILES[@]}; FILES+=("$dest"); if [[ -e $dest ]]; then cp -a "$dest" "$STAGE/backup-$n"; EXISTED+=(1); else EXISTED+=(0); fi; }
rollback(){
  local status=$?; trap - EXIT INT TERM
  if ((status!=0 && CHANGED)); then
    echo 'VoS: installation failed; restoring managed files and service state' >&2
    for unit in "${UNITS[@]}"; do systemctl stop "$unit" >/dev/null 2>&1 || true; done
    for ((n=${#FILES[@]}-1;n>=0;n--)); do
      if [[ ${EXISTED[$n]} == 1 ]]; then cp -a "$STAGE/backup-$n" "${FILES[$n]}"; else rm -f "${FILES[$n]}"; fi
    done
    systemctl daemon-reload || true
    for unit in "${UNITS[@]}"; do
      if [[ ${WAS_ENABLED[$unit]} == enabled ]]; then systemctl enable "$unit" >/dev/null 2>&1 || true; else systemctl disable "$unit" >/dev/null 2>&1 || true; fi
      if [[ ${WAS_ACTIVE[$unit]} == active ]]; then systemctl start "$unit" || true; fi
    done
    if ((FIREWALL_ADDED)); then ufw --force delete allow "$SSH_PORT/tcp" || true; fi
    rmdir "$BASE/authorized_keys" "$BASE" /usr/local/lib/vos 2>/dev/null || true
  fi
  rm -rf "$STAGE"
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
render_relay > "$STAGE/relay.json"
"$BINARY" relay validate --config "$STAGE/relay.json"
if ((!REUSE_SSH)); then render_ssh > "$STAGE/sshd_config"; /usr/sbin/sshd -t -f "$STAGE/sshd_config"; fi
cat > "$STAGE/relay.service" <<EOF
# $MANAGED
[Unit]
Description=VoS loopback TCP/UDP relay
After=network-online.target
Wants=network-online.target
[Service]
User=vos-relay
Group=vos-relay
RuntimeDirectory=vos
RuntimeDirectoryMode=0750
ExecStart=$BIN relay run --config $BASE/relay.json --lock-file /run/vos/relay.lock
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
cat > "$STAGE/ssh.service" <<EOF
# $MANAGED
[Unit]
Description=VoS dedicated SSH transport
After=network-online.target vos-relay.service
Wants=network-online.target vos-relay.service
[Service]
ExecStartPre=/usr/sbin/sshd -t -f $BASE/sshd_config
ExecStart=/usr/sbin/sshd -D -e -f $BASE/sshd_config
Restart=on-failure
RestartSec=3
KillMode=control-group
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
EOF
backup "$BIN"; backup "$BASE/relay.json"; backup "$RELAY_UNIT"; backup "$MARKER"
if ((!REUSE_SSH)); then backup "$BASE/sshd_config"; backup "$SSH_UNIT"; backup "$BASE/authorized_keys/$SSH_USER"; fi
CHANGED=1
install -d -m 0755 "$BASE" /usr/local/lib/vos
install -m 0755 "$BINARY" "$BIN.next"
mv -f "$BIN.next" "$BIN"
install -o root -g vos-relay -m 0640 "$STAGE/relay.json" "$BASE/relay.json"
install -m 0644 "$STAGE/relay.service" "$RELAY_UNIT"
printf '%s\n' "$MANAGED" > "$MARKER"
if ((!REUSE_SSH)); then
  install -d -m 0755 "$BASE/authorized_keys"
  install -m 0644 "$PUBLIC_KEY" "$BASE/authorized_keys/$SSH_USER"
  install -m 0600 "$STAGE/sshd_config" "$BASE/sshd_config"
  install -m 0644 "$STAGE/ssh.service" "$SSH_UNIT"
  if ((OPEN_FIREWALL)) && command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    if ! ufw status | awk '{print $1}' | grep -qx "$SSH_PORT/tcp"; then
      ufw allow "$SSH_PORT/tcp"; FIREWALL_ADDED=1
    fi
  fi
fi
systemctl daemon-reload
systemctl enable "${UNITS[@]}"
systemctl restart "${UNITS[@]}"
for unit in "${UNITS[@]}"; do systemctl is-active --quiet "$unit" || die "$unit did not start"; done
for _ in {1..20}; do
  if [[ -n $(ss -H -ltn "sport = :$RELAY_PORT") ]]; then break; fi
  sleep 0.25
done
[[ -n $(ss -H -ltn "sport = :$RELAY_PORT") ]] || die "relay listener is absent"
if ((!REUSE_SSH)); then [[ -n $(ss -H -ltn "sport = :$SSH_PORT") ]] || die "SSH listener is absent"; fi
CHANGED=0
echo "VoS installed: relay 127.0.0.1:$RELAY_PORT, SSH TCP $SSH_PORT"
if ((REUSE_SSH)); then echo 'Existing SSH must allow direct-tcpip forwarding, including 127.0.0.1 relay.'; fi
if ((REUSE_SSH)); then
  echo 'System OpenSSH Ed25519 public key below; verify that the existing listener uses it:'
else
  echo 'Trusted server host key (verify over this administrative connection):'
fi
cat /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
echo 'Packages and newly created service/login accounts are retained if installation fails.'
