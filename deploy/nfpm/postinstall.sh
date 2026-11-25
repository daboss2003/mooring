#!/bin/sh
# Runs after `apt install mooring` / `dnf install mooring`. It creates the service
# account and directories Mooring needs, but does NOT start the service — the operator
# must first write /etc/mooring/config.yaml (the master key, login, and IP allowlist
# are generated over SSH; see /usr/share/mooring/config.example.yaml).
set -e

# Dedicated low-privilege service user, in the docker group so it can talk to Docker.
if ! getent group mooring >/dev/null 2>&1; then
    groupadd --system mooring
fi
if ! getent passwd mooring >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid mooring mooring
fi
if getent group docker >/dev/null 2>&1; then
    usermod -aG docker mooring || true
fi

# Config dir (root-owned, group-readable by the service) and state dir (private).
install -d -o root -g mooring -m 0750 /etc/mooring
install -d -o mooring -g mooring -m 0700 /var/lib/mooring
# App run dirs (a sibling of the state dir by design) and the supervised edge's
# data/cert store. Both must exist + be mooring-writable + be in the unit's
# ReadWritePaths, or deploys can't materialize and Caddy can't write its certs.
install -d -o mooring -g mooring -m 0700 /var/lib/mooring-apps
install -d -o mooring -g mooring -m 0700 /var/lib/caddy

# The adm group lets security logs read the host's auth.log, fail2ban.log and the journal. It is
# added once: the marker keeps an upgrade from re-adding a membership the operator removed (after
# that, `sudo mooring setup --yes` adds it again). The marker is root's, in /etc/mooring, where the
# service user can't remove it. A user already in adm only gets the marker; a failed usermod
# leaves none, so the next upgrade tries again.
ADM_MARKER=/etc/mooring/.adm-group-added
if getent group adm >/dev/null 2>&1 && [ ! -e "$ADM_MARKER" ]; then
    case " $(id -nG mooring 2>/dev/null) " in
        *" adm "*) adm_ok=yes ;;
        *) if usermod -aG adm mooring; then adm_ok=yes; else adm_ok=no; fi ;;
    esac
    if [ "$adm_ok" = yes ]; then
        (umask 077 && : > "$ADM_MARKER") || true
    fi
fi

# Pick up the shipped unit. On an UPGRADE of an already-configured install, keep boot-start
# ENABLED and bring the new binary up — an update must NEVER silently disable boot-start or leave
# the service stopped (the presence of /etc/mooring/config.yaml means Mooring is already set up, so
# this is an upgrade/reinstall, not a first install). daemon-reload loads the new unit (its
# MemoryMax, GOMEMLIMIT and SupplementaryGroups), and the restart starts the service with it and
# with the groups added above. A unit copied to /etc/systemd/system, or a drop-in, overrides the
# shipped one; `mooring doctor` reports a MemoryMax that stayed below 1G. A fresh install has no
# config yet and is left for the operator to enable after writing config.yaml (see the steps
# printed below).
#
# Before the restart the NEW binary checks the existing config.yaml. A new version can refuse a
# file the old one accepted; restarting then would stop a working service and leave it down. When
# the file is refused (exit status 78) nothing is restarted: the old process keeps running and the
# problem is printed with the commands to run after fixing it. Any other result (valid, or the
# check itself could not run) restarts as before; a refused file can't crash-loop either way,
# because the unit doesn't restart on 78.
# The check runs as the service user when it can: serve runs as that user, while root reads a file
# the service can't. It runs with the unit's group too (`-g mooring`, the unit's Group=): runuser
# alone uses the user's primary group from the passwd database, which need not be that group, and
# the file's group rule compares against it. When runuser is missing, or doesn't take -g, or the
# user doesn't exist, the check runs as root. As the service user, exit status 2 (the file can't be
# read) also means serve would not start, so it is handled like 78. As root only 78 is (root's
# check also reports a file the service can't read, or of another group, as 78).
# Every command here is guarded: this script runs under `set -e` and must never fail the install.
# upgrade-restart: begin
MOORING_BIN=/usr/local/bin/mooring
MOORING_CONFIG=/etc/mooring/config.yaml
mooring_check_as_service=no
if command -v runuser >/dev/null 2>&1 && id -u mooring >/dev/null 2>&1; then
    # A probe: does this runuser run a command as the user with the group?
    if runuser -u mooring -g mooring -- true >/dev/null 2>&1; then
        mooring_check_as_service=yes
    fi
fi
# mooring_config_check [flags]: `mooring config check` on the config, as the service user when possible.
mooring_config_check() {
    if [ "$mooring_check_as_service" = yes ]; then
        runuser -u mooring -g mooring -- "$MOORING_BIN" config check "$@" --config "$MOORING_CONFIG"
    else
        "$MOORING_BIN" config check "$@" --config "$MOORING_CONFIG"
    fi
}
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    if [ -f "$MOORING_CONFIG" ]; then
        systemctl enable mooring >/dev/null 2>&1 || true
        config_rc=0
        mooring_config_check --quiet >/dev/null 2>&1 || config_rc=$?
        config_refused=no
        if [ "$config_rc" -eq 78 ]; then
            config_refused=yes
        elif [ "$config_rc" -eq 2 ] && [ "$mooring_check_as_service" = yes ]; then
            config_refused=yes
        fi
        if [ "$config_refused" = yes ]; then
            echo "" || true
            echo "mooring: NOT restarted. This version refuses $MOORING_CONFIG:" || true
            echo "" || true
            mooring_config_check 2>&1 || true
            echo "" || true
            if systemctl is-active --quiet mooring >/dev/null 2>&1; then
                echo "The service that was running keeps running on the previous version until it is" || true
                echo "restarted; it will not start again with this file. Fix the file, then run:" || true
            else
                echo "The service is not running, and it will not start with this file. Fix the file," || true
                echo "then run:" || true
            fi
            echo "  sudo mooring config check" || true
            echo "  sudo systemctl restart mooring" || true
            echo "" || true
        else
            systemctl restart mooring >/dev/null 2>&1 || true
        fi
    fi
fi
# upgrade-restart: end

# Only print the first-run setup steps on a FRESH install (no config yet) — not on every upgrade.
if [ ! -f /etc/mooring/config.yaml ]; then
cat <<'EOF'

Mooring installed. Next steps (over SSH):
  1. Install Caddy:      sudo mooring setup --yes
                         (the managed edge supervises a child Caddy; this installs
                          Caddy's official release, or upgrades an older Caddy to
                          it. The unit already grants the bind capability + creates
                          its runtime dirs, so nothing else is needed.)
  2. Generate secrets:   mooring gen-key ; mooring hash-password
  3. Write the config:   /etc/mooring/config.yaml
                         (template at /usr/share/mooring/config.example.yaml)
  4. Start it:           systemctl enable --now mooring
  5. Verify:             mooring doctor

Docs: https://github.com/daboss2003/mooring/tree/main/docs
EOF
fi
