#!/usr/bin/env bash
# OVERLORD installer — run with sudo from the repo root:
#   sudo bash packaging/install.sh
#
# Installs:
#   /usr/local/lib/overlord/overlord.py   the engine
#   /usr/local/bin/overlord               compiled ELF launcher (AppArmor attachment point)
#   /etc/apparmor.d/overlord              userns grant -> enables kernel backend
#   deps: fuse-overlayfs (fallback backend), strace (--trace recorder)
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "error: run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo "== dependencies"
if command -v apt-get > /dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends fuse-overlayfs strace gcc libc6-dev
fi

echo "== engine"
install -d /usr/local/lib/overlord
install -m 0644 "$HERE/overlord.py" /usr/local/lib/overlord/overlord.py
install -m 0644 "$HERE/agent.py" /usr/local/lib/overlord/agent.py
install -m 0644 "$HERE/providers.py" /usr/local/lib/overlord/providers.py
install -m 0644 "$HERE/review.py" /usr/local/lib/overlord/review.py
install -m 0644 "$HERE/mcp.py" /usr/local/lib/overlord/mcp.py
install -m 0644 "$HERE/memory.py" /usr/local/lib/overlord/memory.py
install -m 0644 "$HERE/auth.py" /usr/local/lib/overlord/auth.py
install -m 0644 "$HERE/cost.py" /usr/local/lib/overlord/cost.py
install -m 0644 "$HERE/audit.py" /usr/local/lib/overlord/audit.py
install -m 0644 "$HERE/retention.py" /usr/local/lib/overlord/retention.py
install -m 0644 "$HERE/skills.py" /usr/local/lib/overlord/skills.py
install -m 0644 "$HERE/oidc.py" /usr/local/lib/overlord/oidc.py
install -m 0644 "$HERE/notify.py" /usr/local/lib/overlord/notify.py
install -m 0644 "$HERE/vault.py" /usr/local/lib/overlord/vault.py
install -m 0644 "$HERE/bundle.py" /usr/local/lib/overlord/bundle.py
install -m 0644 "$HERE/netproxy.py" /usr/local/lib/overlord/netproxy.py
install -m 0644 "$HERE/policycheck.py" /usr/local/lib/overlord/policycheck.py
install -m 0644 "$HERE/ui.py" /usr/local/lib/overlord/ui.py
install -m 0644 "$HERE/chatui.py" /usr/local/lib/overlord/chatui.py
install -m 0644 "$HERE/packaging/ebpf/provenance.bt" /usr/local/lib/overlord/provenance.bt
install -m 0644 "$HERE/sdk/overlord_client.py" /usr/local/lib/overlord/overlord_client.py

echo "== launcher"
gcc -O2 -o /usr/local/bin/overlord "$HERE/packaging/launcher.c"
chmod 0755 /usr/local/bin/overlord

echo "== apparmor profile (kernel backend enablement)"
if [[ -d /etc/apparmor.d ]] && command -v apparmor_parser > /dev/null; then
    install -m 0644 "$HERE/packaging/apparmor/overlord" /etc/apparmor.d/overlord
    if apparmor_parser -r /etc/apparmor.d/overlord 2>/dev/null; then
        echo "   profile loaded"
    else
        # WSL2 and other kernels without AppArmor: the parser fails, the file is
        # in place for a kernel that has it, and `doctor` decides the backend
        echo "   profile not loaded (this kernel has no AppArmor — normal on WSL2; overlord doctor decides the backend)"
    fi
else
    echo "   apparmor not present — skipping (fuse backend will be used)"
fi

echo "== doctor (as invoking user)"
REAL_USER="${SUDO_USER:-root}"
su "$REAL_USER" -c "/usr/local/bin/overlord doctor" || true

echo
echo "OVERLORD installed. Try:"
echo "  overlord run -t <dir> -- <command>"
