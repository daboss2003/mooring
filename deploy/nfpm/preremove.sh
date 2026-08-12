#!/bin/sh
# Runs before the package is removed OR upgraded. Disable + stop the service ONLY on a REAL
# removal — never on an upgrade. dpkg (deb) and rpm both run the OLD package's pre-remove script
# during an upgrade; disabling there reset the operator's `systemctl enable` on EVERY update (a
# long-standing packaging bug where the boot-start toggle silently flipped off after each upgrade).
#
# The removal action is passed as $1:
#   deb:  remove | purge | upgrade | deconfigure | failed-upgrade
#   rpm:  0 (uninstall) | 1 (upgrade)
#
# The config and data dirs are intentionally left in place even on removal (removing them would
# destroy the operator's keys, secrets, and state) — delete /etc/mooring and /var/lib/mooring by
# hand for a full wipe.
set -e

case "${1:-remove}" in
    remove | purge | 0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now mooring >/dev/null 2>&1 || true
        fi
        ;;
    *)
        # upgrade / deconfigure / other — leave the service enabled + running so the update is
        # seamless. The new package's postinstall brings the new binary up.
        :
        ;;
esac
