# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

FROM debian:bookworm-slim
ARG TARGETARCH
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server iproute2 systemd procps shellcheck ca-certificates python3 && rm -rf /var/lib/apt/lists/*
COPY tests/server/systemctl /usr/local/bin/systemctl
COPY tests/server/test.sh /test.sh
COPY tests/server/fixtures.py /fixtures.py
COPY tests/server/tun-smoke.sh /tun-smoke.sh
COPY server/install.sh /install.sh
COPY bin/vos-linux-${TARGETARCH} /vos
RUN chmod +x /usr/local/bin/systemctl /test.sh /vos && mkdir -p /run/systemd/system /run/sshd
CMD ["bash", "/test.sh"]
