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

[ "$(id -u)" -eq 0 ] || { echo "error: run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo "== dependencies"
if command -v apt-get > /dev/null; then
    apt-get install -y --no-install-recommends fuse-overlayfs strace gcc libc6-dev
fi

echo "== engine"
install -d /usr/local/lib/overlord
install -m 0644 "$HERE/overlord.py" /usr/local/lib/overlord/overlord.py

echo "== launcher"
gcc -O2 -o /usr/local/bin/overlord "$HERE/packaging/launcher.c"
chmod 0755 /usr/local/bin/overlord

echo "== apparmor profile (kernel backend enablement)"
if [ -d /etc/apparmor.d ] && command -v apparmor_parser > /dev/null; then
    install -m 0644 "$HERE/packaging/apparmor/overlord" /etc/apparmor.d/overlord
    apparmor_parser -r /etc/apparmor.d/overlord
    echo "   profile loaded"
else
    echo "   apparmor not present — skipping (fuse backend will be used)"
fi

echo "== doctor (as invoking user)"
REAL_USER="${SUDO_USER:-root}"
su "$REAL_USER" -c "/usr/local/bin/overlord doctor" || true

echo
echo "OVERLORD installed. Try:"
echo "  overlord run -t <dir> -- <command>"
