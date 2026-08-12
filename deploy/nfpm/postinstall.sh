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

# Pick up the shipped unit. On an UPGRADE of an already-configured install, keep boot-start
# ENABLED and bring the new binary up — an update must NEVER silently disable boot-start or leave
# the service stopped (the presence of /etc/mooring/config.yaml means Mooring is already set up, so
# this is an upgrade/reinstall, not a first install). A fresh install has no config yet and is left
# for the operator to enable after writing config.yaml (see the steps printed below).
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    if [ -f /etc/mooring/config.yaml ]; then
        systemctl enable mooring >/dev/null 2>&1 || true
        systemctl restart mooring >/dev/null 2>&1 || true
    fi
fi

# Only print the first-run setup steps on a FRESH install (no config yet) — not on every upgrade.
if [ ! -f /etc/mooring/config.yaml ]; then
cat <<'EOF'

Mooring installed. Next steps (over SSH):
  1. Install Caddy:      sudo mooring setup --yes
                         (the managed edge supervises a child Caddy; this installs
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
