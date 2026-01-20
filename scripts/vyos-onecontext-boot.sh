#!/bin/sh
# VyOS Sagitta OpenNebula Contextualization Boot Script
#
# This script is invoked by vyos-postconfig-bootup.script to apply OpenNebula
# context to the VyOS router configuration.
#
# IMPORTANT: The Python module MUST run with the 'vyattacfg' group to access
# VyOS configuration APIs. Using sudo will break manual configuration sessions.
#
# This script handles:
# 1. Group verification (re-exec with 'sg vyattacfg' if needed)
# 2. Python venv activation
# 3. Running the contextualization module
# 4. Error handling and logging

set -e

# Configuration
VENV_PATH="/opt/vyos-onecontext/venv"
CONTEXT_PATH="/var/run/one-context/one_env"
LOG_TAG="vyos-onecontext"

# Log to syslog and serial port for visibility in integration tests
# Try multiple output targets to ensure visibility
log_info() {
    logger -t "$LOG_TAG" -p local0.info "$1"
    echo "$LOG_TAG: $1" >/dev/ttyS0 2>/dev/null || true
    echo "$LOG_TAG: $1" >/dev/console 2>/dev/null || true
}

log_error() {
    logger -t "$LOG_TAG" -p local0.err "$1"
    echo "$LOG_TAG: ERROR: $1" >/dev/ttyS0 2>/dev/null || true
    echo "$LOG_TAG: ERROR: $1" >/dev/console 2>/dev/null || true
}

log_debug() {
    logger -t "$LOG_TAG" -p local0.debug "$1"
    # Debug messages only go to syslog, not console
}

# Check if we have vyattacfg group membership
has_vyattacfg_group() {
    # Get the vyattacfg GID
    VYATTACFG_GID=$(getent group vyattacfg | cut -d: -f3)
    if [ -z "$VYATTACFG_GID" ]; then
        return 1
    fi

    # Check if it's our effective GID or in supplementary groups
    if [ "$(id -g)" = "$VYATTACFG_GID" ]; then
        return 0
    fi

    # Check supplementary groups
    id -G | tr ' ' '\n' | grep -q "^${VYATTACFG_GID}$"
}

# Main function
main() {
    log_info "Starting VyOS contextualization"

    # Verify vyattacfg group is available
    if ! getent group vyattacfg >/dev/null 2>&1; then
        log_error "vyattacfg group does not exist. Is this a VyOS system?"
        exit 1
    fi

    # Re-exec with vyattacfg group if needed
    if ! has_vyattacfg_group; then
        log_debug "Re-executing with vyattacfg group"
        # Properly quote script path and all arguments to prevent shell injection
        cmd="$(printf '%q' "$0")"
        for arg in "$@"; do
            cmd="$cmd $(printf '%q' "$arg")"
        done
        exec sg vyattacfg -c "$cmd"
    fi

    # Verify Python venv exists
    if [ ! -d "$VENV_PATH" ]; then
        log_error "Python venv not found at $VENV_PATH"
        exit 1
    fi

    if [ ! -x "$VENV_PATH/bin/python" ]; then
        log_error "Python interpreter not found in venv"
        exit 1
    fi

    # Check for context file (not an error if missing on fresh boot)
    if [ ! -f "$CONTEXT_PATH" ]; then
        log_info "Context file not found at $CONTEXT_PATH. Skipping."
        exit 0
    fi

    # Run the Python module
    log_info "Applying context from $CONTEXT_PATH"

    # Capture output for logging
    OUTPUT_FILE=$(mktemp)
    trap 'rm -f "$OUTPUT_FILE"' EXIT

    if "$VENV_PATH/bin/python" -m vyos_onecontext "$CONTEXT_PATH" >"$OUTPUT_FILE" 2>&1; then
        log_info "Contextualization completed successfully"
        # Log Python output at INFO level so VYOS_CMD lines appear in serial log
        if [ -s "$OUTPUT_FILE" ]; then
            while IFS= read -r line; do
                log_info "$line"
            done < "$OUTPUT_FILE"
        fi
        exit 0
    else
        EXIT_CODE=$?
        log_error "Contextualization failed with exit code $EXIT_CODE"
        if [ -s "$OUTPUT_FILE" ]; then
            log_error "Output: $(cat "$OUTPUT_FILE")"
        fi
        exit $EXIT_CODE
    fi
}

# Run main function
main "$@"
