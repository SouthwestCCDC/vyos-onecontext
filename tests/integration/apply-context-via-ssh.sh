#!/bin/bash
# Apply context configuration via SSH to a running VyOS VM
#
# This script reads a context .env file, uploads it to the VM,
# and runs vyos-onecontext to apply the configuration.
#
# Usage: apply-context-via-ssh.sh <context-file.env>

set -euo pipefail

CONTEXT_FILE="${1:?Context file path required}"

# Check for required dependencies
if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is required but not found" >&2
    exit 1
fi

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
#!/bin/vbash
source /opt/vyatta/etc/functions/script-template

CONTEXT_FILE="$1"

# vyos-onecontext expects the context file at a specific location
mkdir -p /var/run/one-context
cp "$CONTEXT_FILE" /var/run/one-context/one_env

# Clean up any stale config session from initial boot
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end 2>/dev/null || true

# Run the Python module directly
# No 'sg' needed - script-template sets up vyattacfg group access
# Running in vbash with script-template ensures full VyOS environment (validators, PATH, etc.)
OUTPUT=$(/opt/vyos-onecontext/venv/bin/python -m vyos_onecontext -v /var/run/one-context/one_env 2>&1) || EXIT_CODE=$?
EXIT_CODE=${EXIT_CODE:-0}

# Echo output to stdout for debugging
echo "$OUTPUT"

# Write each line to serial port for validation assertions
echo "$OUTPUT" | while IFS= read -r line; do
    echo "vyos-onecontext: $line" > /dev/ttyS0 2>/dev/null || true
done

# Write completion/failure markers to serial port
if [ $EXIT_CODE -eq 0 ]; then
    echo "vyos-onecontext: Contextualization completed successfully" > /dev/ttyS0 2>/dev/null || true
    echo "APPLY_COMPLETE"
    exit 0
else
    echo "vyos-onecontext: Contextualization failed with exit code $EXIT_CODE" > /dev/ttyS0 2>/dev/null || true
    echo "APPLY_FAILED: exit code $EXIT_CODE"
    exit $EXIT_CODE
fi
APPLY_EOF
)

# Use unique temp file to avoid clobbering across concurrent runs
APPLY_LOG=$(mktemp)

if ssh_command "sudo /bin/vbash -s -- $REMOTE_CONTEXT" <<< "$APPLY_SCRIPT" 2>&1 | tee "$APPLY_LOG"; then
    if grep -q "APPLY_COMPLETE" "$APPLY_LOG"; then
        echo "[PASS] Configuration applied successfully"

        # Clean up remote context file and local log
        ssh_command "rm -f $REMOTE_CONTEXT" || true
        rm -f "$APPLY_LOG"

        exit 0
    else
        echo "[FAIL] Configuration application did not complete"
        cat "$APPLY_LOG"

        # Clean up remote context file and local log
        ssh_command "rm -f $REMOTE_CONTEXT" || true
        rm -f "$APPLY_LOG"

        exit 1
    fi
else
    EXIT_CODE=$?
    echo "[FAIL] Configuration application failed with exit code $EXIT_CODE"
    cat "$APPLY_LOG"

    # Clean up remote context file and local log
    ssh_command "rm -f $REMOTE_CONTEXT" || true
    rm -f "$APPLY_LOG"

    # For error scenarios, exit code 1 might be expected
    # Let the calling script decide how to handle this
    exit $EXIT_CODE
fi
