#!/bin/bash
# Test the basic group prototype
#
# This script is a convenience wrapper to test the group testing functionality
# with the "basic" group (simple, quotes, multi-interface).
#
# Usage: test-basic-group.sh <vyos-image.qcow2>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VYOS_IMAGE="${1:?VyOS image path required}"

if [ ! -f "$VYOS_IMAGE" ]; then
    echo "ERROR: VyOS image not found: $VYOS_IMAGE"
    exit 1
fi

echo "Testing Basic Group with grouped test approach..."
echo ""

# Measure time for grouped approach
START_TIME=$(date +%s)

"$SCRIPT_DIR/run-qemu-group-test.sh" "$VYOS_IMAGE" basic simple quotes multi-interface

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "========================================"
echo "  Performance Results"
echo "========================================"
echo "Group test time: ${ELAPSED}s ($(($ELAPSED / 60))m $(($ELAPSED % 60))s)"
echo ""
echo "For comparison, individual tests would take:"
echo "  3 fixtures × ~150s = ~450s (7m 30s)"
echo ""

if [ $ELAPSED -lt 300 ]; then
    SPEEDUP=$(echo "scale=2; 450 / $ELAPSED" | bc)
    echo "Speedup: ${SPEEDUP}x faster"
    echo "[SUCCESS] Group testing is significantly faster!"
else
    echo "[INFO] Group testing took longer than expected"
    echo "       This might be due to system load or configuration issues"
fi
