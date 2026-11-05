#!/bin/sh
# The service's user and its configuration directory. The service is neither
# enabled nor started: it needs a server.yaml and an environment file first.
set -e
getent passwd ligo >/dev/null || useradd --system --user-group --home-dir /var/lib/ligo --no-create-home --shell /usr/sbin/nologin ligo
install -d -o root -g ligo -m 0750 /etc/ligo
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi
