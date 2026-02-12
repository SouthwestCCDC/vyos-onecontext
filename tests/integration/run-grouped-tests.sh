#!/bin/bash
# Run all integration tests in groups to reduce VM boot overhead
#
# This script organizes fixtures into logical groups and runs each group
# using run-qemu-group-test.sh, which boots one VM per group instead of
# one VM per fixture.
#
# Usage: run-grouped-tests.sh <vyos-image.qcow2> [fixtures...]
#
# Arguments:
#   vyos-image.qcow2: Path to VyOS image
#   fixtures...:      Optional list of specific fixtures to run (without .env)
#                     If "all" or no fixtures specified, runs all fixtures
#                     Example: run-grouped-tests.sh vyos.qcow2 simple dhcp nat-full

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

# Define test groups based on design document (GROUP-TESTING.md)
# Each group is defined as "name:fixture1,fixture2,fixture3"
declare -a TEST_GROUPS=(
    "basic:simple,quotes,multi-interface"
    "routing:static-routes,management-vrf,ospf"
    "nat:snat,dnat,nat-full,nat-with-firewall"
    "services:dhcp,start-script,ssh-keys"
    "errors:invalid-json,missing-required-fields,partial-valid"
)

# Note: vrf-with-routing is currently disabled due to issue #171
# It can be re-enabled once that bug is fixed
# "complex:vrf-with-routing"

# Function to check if a fixture is in the selected list
is_fixture_selected() {
    local fixture="$1"

    # If no fixtures specified or "all" specified, select everything
    if [ ${#SELECTED_FIXTURES[@]} -eq 0 ] || [[ " ${SELECTED_FIXTURES[*]} " =~ " all " ]]; then
        return 0
    fi

    # Check if fixture is in selected list
    for selected in "${SELECTED_FIXTURES[@]}"; do
        if [ "$fixture" = "$selected" ]; then
            return 0
        fi
    done

    return 1
}

# Filter groups to only include selected fixtures
GROUPS_TO_RUN=()

for group_def in "${TEST_GROUPS[@]}"; do
    IFS=':' read -r group_name fixtures_str <<< "$group_def"
    IFS=',' read -ra fixtures <<< "$fixtures_str"

    # Filter fixtures in this group
    selected_in_group=()
    for fixture in "${fixtures[@]}"; do
        if is_fixture_selected "$fixture"; then
            selected_in_group+=("$fixture")
        fi
    done

    # If any fixtures from this group are selected, add to groups to run
    if [ ${#selected_in_group[@]} -gt 0 ]; then
        GROUPS_TO_RUN+=("$group_name:${selected_in_group[*]}")
    fi
done

if [ ${#GROUPS_TO_RUN[@]} -eq 0 ]; then
    echo "ERROR: No matching fixtures found"
    if [ ${#SELECTED_FIXTURES[@]} -gt 0 ]; then
        echo "Selected: ${SELECTED_FIXTURES[*]}"
    fi
    exit 1
fi

echo "========================================"
echo "  VyOS Grouped Integration Tests"
echo "========================================"
echo "Image: $VYOS_IMAGE"
echo "Groups: ${#GROUPS_TO_RUN[@]}"
echo ""

TOTAL_GROUPS=${#GROUPS_TO_RUN[@]}
GROUPS_PASSED=0
GROUPS_FAILED=0
TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0

# Run each group
for i in "${!GROUPS_TO_RUN[@]}"; do
    group_def="${GROUPS_TO_RUN[$i]}"
    IFS=':' read -r group_name fixtures_str <<< "$group_def"
    # Convert space-separated back to array
    read -ra fixtures <<< "$fixtures_str"

    group_num=$((i + 1))

    echo "========================================"
    echo "Group $group_num/$TOTAL_GROUPS: $group_name"
    echo "========================================"
    echo "Fixtures: ${fixtures[*]}"
    echo ""

    # Run the group test
    if "$SCRIPT_DIR/run-qemu-group-test.sh" "$VYOS_IMAGE" "$group_name" "${fixtures[@]}"; then
        echo ""
        echo "[PASS] Group $group_name passed"
        ((GROUPS_PASSED++)) || true
        ((TOTAL_PASSED += ${#fixtures[@]})) || true
    else
        echo ""
        echo "[FAIL] Group $group_name failed"
        ((GROUPS_FAILED++)) || true
        # Individual fixture failures are tracked within run-qemu-group-test.sh
        # We count the whole group as failed fixtures for overall stats
        ((TOTAL_FAILED += ${#fixtures[@]})) || true
    fi

    ((TOTAL_TESTS += ${#fixtures[@]})) || true
    echo ""
done

echo "========================================"
echo "  Overall Test Results"
echo "========================================"
echo "Groups:        $TOTAL_GROUPS (passed: $GROUPS_PASSED, failed: $GROUPS_FAILED)"
echo "Total tests:   $TOTAL_TESTS"
echo ""

if [ $GROUPS_FAILED -eq 0 ]; then
    echo "[PASS] All test groups passed!"
    exit 0
else
    echo "[FAIL] Some test groups failed"
    exit 1
fi
