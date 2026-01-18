#!/bin/bash
# Run all QEMU integration tests
#
# This script runs all test scenarios with different context files.
#
# Usage: run-all-tests.sh <vyos-image.qcow2>

set -euo pipefail

VYOS_IMAGE="${1:?VyOS image path required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Validate VyOS image exists
if [ ! -f "$VYOS_IMAGE" ]; then
    echo "ERROR: VyOS image not found: $VYOS_IMAGE"
    exit 1
fi

# Validate required scripts exist (create-test-iso.sh comes from PR #52)
if [ ! -x "$SCRIPT_DIR/create-test-iso.sh" ]; then
    echo "ERROR: create-test-iso.sh not found or not executable"
    echo "       This script requires the integration test fixtures (PR #52)."
    exit 1
fi

# Test scenarios
declare -a TEST_SCENARIOS=(
    "simple:Simple router"
    "quotes:Quote bug regression"
    "multi-interface:Multi-interface router"
)

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

TOTAL_TESTS=${#TEST_SCENARIOS[@]}
PASSED=0
FAILED=0

echo "========================================"
echo "  VyOS Integration Test Suite"
echo "========================================"
echo "Image: $VYOS_IMAGE"
echo "Tests: $TOTAL_TESTS scenarios"
echo ""

for scenario in "${TEST_SCENARIOS[@]}"; do
    IFS=':' read -r name description <<< "$scenario"

    echo "========================================"
    echo "Test: $description"
    echo "========================================"

    CONTEXT_FILE="$SCRIPT_DIR/contexts/${name}.env"
    if [ ! -f "$CONTEXT_FILE" ]; then
        echo "ERROR: Context file not found: $CONTEXT_FILE"
        ((FAILED++)) || true
        continue
    fi

    # Create test ISO
    ISO_PATH="$TEMP_DIR/${name}.iso"
    echo "Creating context ISO..."
    if ! "$SCRIPT_DIR/create-test-iso.sh" "$ISO_PATH" "$CONTEXT_FILE"; then
        echo "ERROR: Failed to create ISO for $name"
        ((FAILED++)) || true
        continue
    fi

    # Run test
    echo ""
    if "$SCRIPT_DIR/run-qemu-test.sh" "$VYOS_IMAGE" "$ISO_PATH"; then
        echo "[PASS] $description"
        ((PASSED++)) || true
    else
        echo "[FAIL] $description"
        ((FAILED++)) || true
    fi

    echo ""
done

echo "========================================"
echo "  Test Results"
echo "========================================"
echo "Total:  $TOTAL_TESTS"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "[PASS] All tests passed!"
    exit 0
else
    echo "[FAIL] Some tests failed"
    exit 1
fi
