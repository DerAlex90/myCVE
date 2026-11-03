#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo "Installation requires root: sudo ./install.sh /path/to/config.json" >&2
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    echo "This installer requires systemd. Other supervisors can run mycve-agent run --config ... directly." >&2
    exit 1
fi
agent_bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
agent_config_source=${1:?Provide the device-specific configuration JSON}
agent_binary_source=${2:-$agent_bundle_dir/mycve-agent}
if [ ! -r "$agent_config_source" ] || [ ! -x "$agent_binary_source" ]; then
    echo "Configuration or executable unavailable" >&2
    exit 1
fi
# Validate the configuration before changing an existing service; do not print it.
"$agent_binary_source" check --config "$agent_config_source"
if systemctl cat mycve-agent.service >/dev/null 2>&1; then
    systemctl stop mycve-agent.service
fi
if ! id mycve-agent >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/mycve-agent --shell /usr/sbin/nologin mycve-agent
fi
install -d -m 0755 /usr/local/lib/mycve-agent
install -d -m 0750 -o root -g mycve-agent /etc/mycve-agent
install -d -m 0700 -o mycve-agent -g mycve-agent /var/lib/mycve-agent
install -m 0755 "$agent_binary_source" /usr/local/lib/mycve-agent/mycve-agent
install -m 0640 -o root -g mycve-agent "$agent_config_source" /etc/mycve-agent/config.json
install -m 0644 "$agent_bundle_dir/mycve-agent.service" /etc/systemd/system/mycve-agent.service
systemctl daemon-reload
systemctl enable --now mycve-agent.service
echo "myCVE agent installed. Status: systemctl status mycve-agent.service"
echo "Logs: journalctl -u mycve-agent.service"
