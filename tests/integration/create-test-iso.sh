#!/bin/bash
# Create a test context ISO for QEMU integration testing
#
# This script creates an ISO image with OpenNebula context variables
# that can be attached to a VyOS VM for integration testing.
#
# Usage: create-test-iso.sh <output.iso> [context-file]

set -euo pipefail

OUTPUT_ISO="${1:-test-context.iso}"
CONTEXT_FILE="${2:-}"

# Create temporary directory for context files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# If context file provided, use it; otherwise create default test context
if [ -n "$CONTEXT_FILE" ] && [ -f "$CONTEXT_FILE" ]; then
    echo "Using provided context file: $CONTEXT_FILE"
    cp "$CONTEXT_FILE" "$TEMP_DIR/context.sh"
else
    echo "Creating default test context"
    cat > "$TEMP_DIR/context.sh" <<'EOF'
# Test context for integration testing
HOSTNAME="test-router"
SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey123456789abcdefghijklmnopqrstuvwxyz admin@test-router"
ONECONTEXT_MODE="stateless"

# Network configuration
ETH0_IP="192.168.122.100"
ETH0_MASK="255.255.255.0"
ETH0_GATEWAY="192.168.122.1"
ETH0_DNS="8.8.8.8"
EOF
fi

# Create ISO using genisoimage (preferred) or mkisofs (fallback)
if command -v genisoimage &> /dev/null; then
    ISO_CMD="genisoimage"
elif command -v mkisofs &> /dev/null; then
    ISO_CMD="mkisofs"
else
    echo "ERROR: Neither genisoimage nor mkisofs found. Please install one of them."
    exit 1
fi

echo "Creating context ISO: $OUTPUT_ISO"
"$ISO_CMD" -o "$OUTPUT_ISO" \
    -V "CONTEXT" \
    -r \
    -J \
    "$TEMP_DIR"

echo "Context ISO created successfully: $OUTPUT_ISO"
ls -lh "$OUTPUT_ISO"
