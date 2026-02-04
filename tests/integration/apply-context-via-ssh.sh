#!/bin/bash
# Apply context configuration via SSH to a running VyOS VM
#
# This script reads a context .env file, uploads it to the VM,
# and runs vyos-onecontext to apply the configuration.
#
# Usage: apply-context-via-ssh.sh <context-file.env>

set -euo pipefail

CONTEXT_FILE="${1:?Context file path required}"

# SSH configuration should be exported by the calling script
if [ -z "${SSH_PORT:-}" ] || [ -z "${SSH_USER:-}" ] || [ -z "${SSH_HOST:-}" ]; then
    echo "ERROR: SSH configuration not set" >&2
    exit 1
fi

if [ ! -f "$CONTEXT_FILE" ]; then
    echo "ERROR: Context file not found: $CONTEXT_FILE" >&2
    exit 1
fi

# Helper function to run SSH commands
ssh_command() {
    # shellcheck disable=SC2086
    sshpass -p "$SSH_PASSWORD" ssh $SSH_OPTS -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "$@"
}

# Helper function to copy files to VM
scp_to_vm() {
    local src="$1"
    local dest="$2"
    # shellcheck disable=SC2086
    sshpass -p "$SSH_PASSWORD" scp $SSH_OPTS -P "$SSH_PORT" "$src" "${SSH_USER}@${SSH_HOST}:$dest"
}

echo "Applying context configuration from: $CONTEXT_FILE"

# Create temporary context file on VM
REMOTE_CONTEXT="/tmp/test-context-$$.sh"

# Upload context file
if ! scp_to_vm "$CONTEXT_FILE" "$REMOTE_CONTEXT"; then
    echo "ERROR: Failed to upload context file" >&2
    exit 1
fi

# Run vyos-onecontext to apply the configuration
# The Python module is already installed in the test VM
echo "Running vyos-onecontext to apply configuration..."

APPLY_SCRIPT=$(cat <<'APPLY_EOF'
#!/bin/bash
set -euo pipefail

CONTEXT_FILE="$1"

# vyos-onecontext expects the context file at a specific location
# Copy it there temporarily
sudo mkdir -p /var/run/one-context
sudo cp "$CONTEXT_FILE" /var/run/one-context/one_env

# Run contextualization via the boot script (handles sg vyattacfg)
if sudo /opt/vyos-onecontext/boot.sh 2>&1; then
    echo "APPLY_COMPLETE"
    exit 0
else
    EXIT_CODE=$?
    echo "APPLY_FAILED: exit code $EXIT_CODE"
    exit $EXIT_CODE
fi
APPLY_EOF
)

if ssh_command "bash -s -- $REMOTE_CONTEXT" <<< "$APPLY_SCRIPT" 2>&1 | tee /tmp/apply-output.log; then
    if grep -q "APPLY_COMPLETE" /tmp/apply-output.log; then
        echo "[PASS] Configuration applied successfully"
        
        # Clean up remote context file
        ssh_command "rm -f $REMOTE_CONTEXT" || true
        
        return 0
    else
        echo "[FAIL] Configuration application did not complete"
        cat /tmp/apply-output.log
        return 1
    fi
else
    EXIT_CODE=$?
    echo "[FAIL] Configuration application failed with exit code $EXIT_CODE"
    cat /tmp/apply-output.log
    
    # For error scenarios, exit code 1 might be expected
    # Let the calling script decide how to handle this
    return $EXIT_CODE
fi
