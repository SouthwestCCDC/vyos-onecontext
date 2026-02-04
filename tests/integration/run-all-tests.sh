#!/bin/bash
# Run all QEMU integration tests
#
# This script runs all test scenarios with different context files.
#
# Usage: run-all-tests.sh <vyos-image.qcow2> [fixtures...]
#
# Arguments:
#   vyos-image.qcow2: Path to VyOS image
#   fixtures...:      Optional list of specific fixtures to run (without .env)
#                     If "all" or no fixtures specified, runs all fixtures
#                     Example: run-all-tests.sh vyos.qcow2 simple dhcp nat-full

set -euo pipefail

VYOS_IMAGE="${1:?VyOS image path required}"
shift  # Remove first argument, leaving optional fixture list
SELECTED_FIXTURES=("$@")  # Remaining arguments are fixture names

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
    "management-vrf:Management VRF"
    "static-routes:Static routing"
    "ospf:OSPF dynamic routing"
    "dhcp:DHCP server"
    "snat:Source NAT (masquerade)"
    "dnat:Destination NAT (port forwarding)"
    "nat-full:Full NAT (SNAT+DNAT+binat)"
    # SKIP: vrf-with-routing test disabled due to VRF command ordering bug (issue #171)
    # "vrf-with-routing:VRF with routing (VRF+static+OSPF)"
    "nat-with-firewall:NAT with firewall zones"
    "start-script:START_SCRIPT execution"
    "invalid-json:Error scenario - Invalid JSON"
    "missing-required-fields:Error scenario - Missing required fields"
    "partial-valid:Error scenario - Partial valid config"
    "ssh-keys:SSH key injection"
)

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Filter scenarios based on selected fixtures
SCENARIOS_TO_RUN=()

if [ ${#SELECTED_FIXTURES[@]} -eq 0 ] || [[ " ${SELECTED_FIXTURES[*]} " =~ " all " ]]; then
    # No filter specified or "all" specified - run all scenarios
    SCENARIOS_TO_RUN=("${TEST_SCENARIOS[@]}")
    echo "Running all fixtures (no filter specified)"
else
    # Filter scenarios to only those specified
    echo "Running selected fixtures: ${SELECTED_FIXTURES[*]}"
    for scenario in "${TEST_SCENARIOS[@]}"; do
        IFS=':' read -r name description <<< "$scenario"
        for selected in "${SELECTED_FIXTURES[@]}"; do
            if [ "$name" = "$selected" ]; then
                SCENARIOS_TO_RUN+=("$scenario")
                break
            fi
        done
    done
fi

TOTAL_TESTS=${#SCENARIOS_TO_RUN[@]}
PASSED=0
FAILED=0

if [ ${#SCENARIOS_TO_RUN[@]} -eq 0 ]; then
    echo "ERROR: No matching fixtures found for: ${SELECTED_FIXTURES[*]}"
    echo "Available fixtures:"
    for scenario in "${TEST_SCENARIOS[@]}"; do
        IFS=':' read -r name description <<< "$scenario"
        echo "  - $name"
    done
    exit 1
fi

echo "========================================"
echo "  VyOS Integration Test Suite"
echo "========================================"
echo "Image: $VYOS_IMAGE"
echo "Tests: $TOTAL_TESTS scenarios"
echo ""

for scenario in "${SCENARIOS_TO_RUN[@]}"; do
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

    # Run test with context name for assertions
    echo ""
    if CONTEXT_NAME="$name" "$SCRIPT_DIR/run-qemu-test.sh" "$VYOS_IMAGE" "$ISO_PATH"; then
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
