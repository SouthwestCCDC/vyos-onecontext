#!/bin/bash
# Reset VyOS configuration to clean state
#
# This script removes all user-configured sections while preserving
# system basics needed for SSH connectivity.
#
# Usage: reset-vyos-config.sh

set -euo pipefail

# SSH configuration should be exported by the calling script
# Expected variables: SSH_PORT, SSH_OPTS, SSH_USER, SSH_HOST, SSH_PASSWORD
if [ -z "${SSH_PORT:-}" ] || [ -z "${SSH_USER:-}" ] || [ -z "${SSH_HOST:-}" ]; then
    echo "ERROR: SSH configuration not set. This script must be sourced from run-qemu-group-test.sh" >&2
    exit 1
fi

# Helper function to run SSH commands on the VM (same as in run-qemu-test.sh)
ssh_command() {
    # shellcheck disable=SC2086
    sshpass -p "$SSH_PASSWORD" ssh $SSH_OPTS -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "$@"
}

echo "Resetting VyOS configuration to clean state..."

# Build reset commands as a multi-line script
RESET_SCRIPT=$(cat <<'RESET_EOF'
#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

# Enter configuration mode
configure

# Delete user-configured sections (preserve system basics)
# Note: We keep system login, ssh, and eth0 with DHCP for connectivity
delete interfaces ethernet eth0 address
delete interfaces ethernet eth0 vrf
delete protocols
delete nat
delete service dhcp-server
delete service ntp
delete firewall
delete vrf
delete policy

# Commit the clean state
commit

# Exit configuration mode
exit

echo "RESET_COMPLETE"
RESET_EOF
)

# Execute reset script via SSH
if ssh_command "sudo bash -c '$RESET_SCRIPT'" 2>&1 | tee /tmp/reset-output.log; then
    if grep -q "RESET_COMPLETE" /tmp/reset-output.log; then
        echo "[PASS] Configuration reset completed"
        return 0
    else
        echo "[FAIL] Configuration reset did not complete properly"
        return 1
    fi
else
    echo "[FAIL] Configuration reset failed"
    cat /tmp/reset-output.log
    return 1
fi
