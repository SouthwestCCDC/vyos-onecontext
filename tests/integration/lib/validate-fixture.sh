#!/bin/bash
# Shared validation library for VyOS integration tests
#
# This library contains validation functions that can be used by both
# individual test runner (run-qemu-test.sh) and group test runner
# (run-qemu-group-test.sh).
#
# Functions support serial log offset to enable validation in group testing
# where multiple fixtures are tested sequentially in one serial log file.
#
# Usage:
#   source tests/integration/lib/validate-fixture.sh
#   SERIAL_LOG_OFFSET=0  # For individual tests, search full log
#   validate_common_markers "$SERIAL_LOG" "$CONTEXT_NAME"
#   validate_fixture_assertions "$CONTEXT_NAME"
#   run_pytest_ssh_tests "$REPO_ROOT"

# Helper function to check for required commands in serial log
# Supports offset for group testing (searches from offset to end of file)
assert_command_generated() {
    local pattern="$1"
    local description="$2"
    local search_cmd="cat"

    # If SERIAL_LOG_OFFSET is set, use tail to skip to that byte offset
    if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
        search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
    fi

    if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*$pattern"; then
        echo "[PASS] $description"
        return 0
    else
        echo "[FAIL] $description - command not generated"
        echo "       Expected pattern: $pattern"
        VALIDATION_FAILED=1
        return 1
    fi
}

# Validate common markers in serial log (contextualization success/errors/exceptions)
# Arguments:
#   $1 - Path to serial log file
#   $2 - Context name (for error scenario detection)
validate_common_markers() {
    local serial_log="$1"
    local context_name="$2"
    local search_cmd="cat"

    # If SERIAL_LOG_OFFSET is set, use tail to skip to that byte offset
    if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
        search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
    fi

    echo "Checking for expected configuration markers in serial log..."

    # Check that contextualization ran
    if $search_cmd "$serial_log" | grep -q "vyos-onecontext"; then
        echo "[PASS] Contextualization script executed"
    else
        echo "[FAIL] Contextualization script did not execute"
        VALIDATION_FAILED=1
    fi

    # Check for errors in contextualization (expected for error scenarios)
    case "$context_name" in
        invalid-json|missing-required-fields|partial-valid)
            # Error scenarios SHOULD have errors
            if $search_cmd "$serial_log" | grep -q "vyos-onecontext.*error\|vyos-onecontext.*ERROR"; then
                echo "[PASS] Contextualization errors detected (expected for error scenario)"
            else
                echo "[FAIL] No contextualization errors detected (expected errors for '$context_name')"
                VALIDATION_FAILED=1
            fi
            ;;
        *)
            # Normal scenarios should NOT have errors
            if $search_cmd "$serial_log" | grep -q "vyos-onecontext.*error\|vyos-onecontext.*ERROR"; then
                echo "[FAIL] Contextualization errors detected"
                VALIDATION_FAILED=1
            else
                echo "[PASS] No contextualization errors detected"
            fi
            ;;
    esac

    # Check for Python exceptions in vyos-onecontext output
    # Matches: "Traceback (most recent", "SomeError:", "SomeException:"
    # Scope to vyos-onecontext lines to avoid false positives from other system logs
    if $search_cmd "$serial_log" | grep "vyos-onecontext" | grep -qE "(Traceback \(most recent|[A-Z][a-zA-Z]*Error:|[A-Z][a-zA-Z]*Exception:)"; then
        echo "[FAIL] Python exceptions detected in vyos-onecontext output"
        VALIDATION_FAILED=1
    else
        echo "[PASS] No Python exceptions detected in vyos-onecontext output"
    fi

    # CRITICAL: Verify configuration commands were actually generated
    # This ensures the test context is properly processed, not just "didn't crash"
    echo ""
    echo "=== Command Generation Validation ==="

    # Check that ANY commands were generated (baseline requirement)
    if $search_cmd "$serial_log" | grep -q "VYOS_CMD:"; then
        local cmd_count
        cmd_count=$($search_cmd "$serial_log" | grep -c "VYOS_CMD:")
        echo "[PASS] Generated $cmd_count configuration commands"
        echo ""
        echo "Commands generated:"
        $search_cmd "$serial_log" | grep "VYOS_CMD:" | sed 's/.*VYOS_CMD: /  /' | head -30
        echo ""
    else
        echo "[CRITICAL FAIL] No configuration commands were generated!"
        echo "This means the test context is not being processed correctly."
        VALIDATION_FAILED=1
    fi
}

# Validate fixture-specific assertions
# This is the large case statement from run-qemu-test.sh (lines ~317-682)
# Arguments:
#   $1 - Context name
validate_fixture_assertions() {
    local context_name="$1"

    echo ""
    echo "=== Context-Specific Assertions ($context_name) ==="

    case "$context_name" in
        simple)
            assert_command_generated "set system host-name" "Hostname configuration"
            assert_command_generated "set interfaces ethernet eth0 address" "Interface eth0 IP address"
            ;;
        quotes)
            assert_command_generated "set system host-name" "Hostname configuration"
            # Note: This test originally validated SSH key quote handling (issue #40)
            # but now uses default VyOS credentials. The parser quote handling is
            # validated by other tests with quoted values.
            ;;
        multi-interface)
            assert_command_generated "set system host-name" "Hostname configuration"
            assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.30" "Primary IP (192.168.122.30)"
            # Verify alias IP is configured (secondary address on eth0)
            assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.31" "Alias IP (192.168.122.31)"
            ;;
        management-vrf)
            assert_command_generated "set system host-name" "Hostname configuration"
            assert_command_generated "set vrf name management table 100" "VRF creation"
            assert_command_generated "set interfaces ethernet eth0 vrf management" "Interface VRF assignment"
            assert_command_generated "set service ssh vrf management" "SSH VRF binding"
            ;;
        static-routes)
            assert_command_generated "set system host-name" "Hostname configuration"

            # Static route validation: Gateway route
            # Fixture: {"interface": "eth0", "destination": "10.0.0.0/8", "gateway": "192.168.122.1"}
            assert_command_generated "set protocols static route 10.0.0.0/8 next-hop 192.168.122.1" "Gateway route (10.0.0.0/8 via 192.168.122.1)"

            # Static route validation: Interface route (no next-hop)
            # Fixture: {"interface": "eth0", "destination": "172.16.0.0/12"}
            assert_command_generated "set protocols static route 172.16.0.0/12 interface eth0" "Interface route (172.16.0.0/12 via eth0)"

            # Negative assertion: Interface route must NOT have next-hop
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*route 172.16.0.0/12.*next-hop"; then
                echo "[FAIL] Interface route 172.16.0.0/12 should not have next-hop"
                VALIDATION_FAILED=1
            else
                echo "[PASS] Interface route 172.16.0.0/12 correctly has no next-hop"
            fi

            # Negative assertion: Gateway route must NOT use 'interface' syntax
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*route 10.0.0.0/8 interface"; then
                echo "[FAIL] Gateway route 10.0.0.0/8 should not use 'interface' syntax"
                VALIDATION_FAILED=1
            else
                echo "[PASS] Gateway route 10.0.0.0/8 correctly uses next-hop syntax"
            fi
            ;;
        ospf)
            assert_command_generated "set system host-name" "Hostname configuration"

            # OSPF router ID validation
            # Fixture: "router_id":"192.168.122.70"
            assert_command_generated "set protocols ospf parameters router-id '192.168.122.70'" "OSPF router ID (192.168.122.70)"

            # OSPF interface area assignment validation
            # Fixture: {"name":"eth0","area":"0.0.0.0","passive":true}
            assert_command_generated "set protocols ospf interface eth0 area '0.0.0.0'" "OSPF interface eth0 in area 0.0.0.0"

            # OSPF passive interface validation
            # Fixture specifies passive:true for eth0
            assert_command_generated "set protocols ospf interface eth0 passive" "OSPF interface eth0 passive"

            # OSPF route redistribution validation
            # Fixture: "redistribute":["connected"]
            assert_command_generated "set protocols ospf redistribute connected" "OSPF redistribute connected routes"

            # OSPF default-information originate validation
            # Fixture: "default_information":{"originate":true,"always":true,"metric":100}
            assert_command_generated "set protocols ospf default-information originate always" "OSPF default-information originate always"
            assert_command_generated "set protocols ospf default-information originate metric '100'" "OSPF default-information metric 100"

            # Negative assertion: Verify only expected redistribution protocols
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*ospf redistribute static"; then
                echo "[FAIL] OSPF should not redistribute static routes (only connected)"
                VALIDATION_FAILED=1
            else
                echo "[PASS] OSPF correctly redistributes only connected routes"
            fi
            ;;
        dhcp)
            assert_command_generated "set system host-name" "Hostname configuration"
            # DHCP shared-network creation for eth0
            assert_command_generated "set service dhcp-server shared-network-name dhcp-eth0" "DHCP shared-network creation"
            # Subnet configuration
            assert_command_generated "set service dhcp-server shared-network-name dhcp-eth0 subnet 10.50.1.0/24" "DHCP subnet configuration"
            # DHCP range configuration
            assert_command_generated "range 0 start 10.50.1.100" "DHCP range start address"
            assert_command_generated "range 0 stop 10.50.1.200" "DHCP range end address"
            # Gateway option (default-router)
            assert_command_generated "default-router 10.50.1.1" "DHCP default router option"
            # DNS servers option
            assert_command_generated "name-server" "DHCP DNS server option"
            # Lease time
            assert_command_generated "lease 3600" "DHCP lease time"
            # Domain name option
            assert_command_generated "domain-name test.local" "DHCP domain name option"
            # Static mapping
            assert_command_generated "static-mapping reserved-host" "DHCP static mapping"
            assert_command_generated "mac-address 00:11:22:33:44:55" "DHCP static mapping MAC address"
            assert_command_generated "ip-address 10.50.1.50" "DHCP static mapping IP address"
            ;;
        snat)
            assert_command_generated "set system host-name" "Hostname configuration"
            # Source NAT rule
            assert_command_generated "set nat source rule 100" "Source NAT rule created"
            assert_command_generated "outbound-interface name eth0" "SNAT outbound interface (eth0)"
            assert_command_generated "source address 10.100.0.0/24" "SNAT source address"
            assert_command_generated "translation address masquerade" "SNAT masquerade translation"
            ;;
        dnat)
            assert_command_generated "set system host-name" "Hostname configuration"
            # Destination NAT rule
            assert_command_generated "set nat destination rule 100" "Destination NAT rule created"
            assert_command_generated "inbound-interface name eth0" "DNAT inbound interface (eth0)"
            assert_command_generated "protocol tcp" "DNAT protocol (tcp)"
            assert_command_generated "destination port 443" "DNAT destination port"
            assert_command_generated "translation address 10.100.0.50" "DNAT translation address"
            ;;
        nat-full)
            assert_command_generated "set system host-name" "Hostname configuration"
            # Source NAT (masquerade)
            assert_command_generated "set nat source rule 100" "Source NAT rule created"
            assert_command_generated "outbound-interface name eth0" "SNAT outbound interface"
            assert_command_generated "translation address masquerade" "SNAT masquerade translation"
            # Destination NAT (port forward)
            assert_command_generated "set nat destination rule 100" "Destination NAT rule created"
            assert_command_generated "destination port 8080" "DNAT destination port"
            assert_command_generated "translation address 10.100.0.80" "DNAT translation address"
            assert_command_generated "translation port 80" "DNAT translation port"
            # Binat (1:1 NAT) - creates both source and destination rules at 500
            assert_command_generated "set nat source rule 500" "Binat source rule created"
            assert_command_generated "set nat destination rule 500" "Binat destination rule created"
            assert_command_generated "source address.*10.100.0.100" "Binat internal address (source rule)"
            assert_command_generated "destination address.*192.168.122.100" "Binat external address (destination rule)"
            ;;
        vrf-with-routing)
            assert_command_generated "set system host-name" "Hostname configuration"
            # Management VRF
            assert_command_generated "set vrf name management" "VRF creation"
            assert_command_generated "set interfaces ethernet eth0 vrf management" "Interface VRF assignment"
            # Static routes in VRF (Sagitta syntax: set vrf name <vrf> protocols static route ...)
            assert_command_generated "set vrf name management protocols static route 10.10.0.0/16" "Static route in VRF"
            # OSPF is disabled in this test (no interfaces available due to single-NIC limitation)
            # Negative assertion: Verify OSPF commands are NOT generated
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols ospf"; then
                echo "[FAIL] OSPF commands should not be generated (OSPF disabled in fixture)"
                VALIDATION_FAILED=1
            else
                echo "[PASS] OSPF correctly not configured (disabled in fixture)"
            fi
            ;;
        nat-with-firewall)
            assert_command_generated "set system host-name" "Hostname configuration"
            # NAT rules
            assert_command_generated "set nat source rule" "NAT rules generated"
            assert_command_generated "outbound-interface name eth0" "NAT outbound interface"
            assert_command_generated "translation address masquerade" "NAT masquerade translation"
            # Firewall zone (single zone - can't test multi-zone with single NIC)
            assert_command_generated "set firewall zone WAN" "WAN zone creation"
            assert_command_generated "default-action drop" "Zone default action"
            # Global state policies
            assert_command_generated "set firewall global-options state-policy" "Global state policy"
            ;;
        start-script)
            assert_command_generated "set system host-name" "Hostname configuration"
            # START_SCRIPT is executed AFTER commit, so we need SSH to verify it ran
            if [ "${SSH_AVAILABLE:-0}" -eq 1 ]; then
                echo ""
                echo "=== START_SCRIPT Validation ==="
                # Check if the marker file was created by START_SCRIPT
                if ssh_command "test -f /tmp/start-script-marker" 2>/dev/null; then
                    echo "[PASS] START_SCRIPT marker file exists"
                    # Verify the content
                    MARKER_CONTENT=$(ssh_command "cat /tmp/start-script-marker" 2>/dev/null)
                    if echo "$MARKER_CONTENT" | grep -q "START_SCRIPT executed"; then
                        echo "[PASS] START_SCRIPT marker file contains expected content"
                    else
                        echo "[FAIL] START_SCRIPT marker file has unexpected content"
                        VALIDATION_FAILED=1
                    fi
                else
                    echo "[FAIL] START_SCRIPT marker file not found - script did not execute"
                    VALIDATION_FAILED=1
                fi
            else
                echo "[WARN] SSH not available - cannot verify START_SCRIPT execution"
            fi
            ;;
        invalid-json)
            echo ""
            echo "=== Error Scenario: Invalid JSON ==="
            assert_command_generated "set system host-name test-invalid-json" "Hostname configuration (valid)"
            assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.90" "Interface eth0 IP (valid)"

            # DHCP should be configured (valid section)
            assert_command_generated "set service dhcp-server" "DHCP server configuration (valid)"

            # Should have error about ROUTES_JSON
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR.*ROUTES_JSON"; then
                echo "[PASS] ROUTES_JSON error logged"
            else
                echo "[FAIL] ROUTES_JSON error not logged"
                VALIDATION_FAILED=1
            fi

            # Should show error summary
            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR SUMMARY"; then
                echo "[PASS] Error summary logged"
            else
                echo "[FAIL] Error summary not logged"
                VALIDATION_FAILED=1
            fi

            # Should NOT have route commands from ROUTES_JSON (invalid section skipped)
            # Note: Default gateway route (0.0.0.0/0) is valid and should be present
            # Check specifically for the route that would come from invalid ROUTES_JSON
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols static route 10.0.0.0/8"; then
                echo "[FAIL] Static route 10.0.0.0/8 should not be generated (invalid ROUTES_JSON)"
                VALIDATION_FAILED=1
            else
                echo "[PASS] Static routes from ROUTES_JSON correctly skipped (invalid JSON)"
            fi

            # Default gateway route should still be present (from ETH0_GATEWAY)
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols static route 0.0.0.0/0 next-hop 192.168.122.1"; then
                echo "[PASS] Default gateway route present (from ETH0_GATEWAY, valid)"
            else
                echo "[FAIL] Default gateway route not present (should be configured from ETH0_GATEWAY)"
                VALIDATION_FAILED=1
            fi
            ;;
        missing-required-fields)
            echo ""
            echo "=== Error Scenario: Missing Required Fields ==="
            assert_command_generated "set system host-name test-missing-fields" "Hostname configuration (valid)"
            assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.91" "Interface eth0 IP (valid)"

            # DHCP should be configured (valid section)
            assert_command_generated "set service dhcp-server" "DHCP server configuration (valid)"

            # Should have error about OSPF_JSON missing required field
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR.*OSPF_JSON"; then
                echo "[PASS] OSPF_JSON error logged"
            else
                echo "[FAIL] OSPF_JSON error not logged"
                VALIDATION_FAILED=1
            fi

            # Should show error summary
            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR SUMMARY"; then
                echo "[PASS] Error summary logged"
            else
                echo "[FAIL] Error summary not logged"
                VALIDATION_FAILED=1
            fi

            # Should NOT have OSPF commands (invalid section skipped)
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols ospf"; then
                echo "[FAIL] OSPF commands should not be generated (missing required field)"
                VALIDATION_FAILED=1
            else
                echo "[PASS] OSPF commands correctly skipped (missing required field)"
            fi
            ;;
        partial-valid)
            echo ""
            echo "=== Error Scenario: Partial Valid Config (Multiple Errors) ==="
            assert_command_generated "set system host-name test-partial-valid" "Hostname configuration (valid)"
            assert_command_generated "set interfaces ethernet eth0 address.*192.168.122.92" "Interface eth0 IP (valid)"

            # DHCP should be configured (valid section)
            assert_command_generated "set service dhcp-server" "DHCP server configuration (valid)"

            # Should have errors about both ROUTES_JSON and OSPF_JSON
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            ROUTES_ERROR_FOUND=0
            OSPF_ERROR_FOUND=0

            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR.*ROUTES_JSON"; then
                echo "[PASS] ROUTES_JSON error logged"
                ROUTES_ERROR_FOUND=1
            else
                echo "[FAIL] ROUTES_JSON error not logged"
                VALIDATION_FAILED=1
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR.*OSPF_JSON"; then
                echo "[PASS] OSPF_JSON error logged"
                OSPF_ERROR_FOUND=1
            else
                echo "[FAIL] OSPF_JSON error not logged"
                VALIDATION_FAILED=1
            fi

            # Should show error summary with multiple errors
            if $search_cmd "$SERIAL_LOG" | grep -q "ERROR SUMMARY"; then
                echo "[PASS] Error summary logged"
            else
                echo "[FAIL] Error summary not logged"
                VALIDATION_FAILED=1
            fi

            # Should NOT have routes from ROUTES_JSON (malformed JSON)
            # Note: Default gateway route (0.0.0.0/0) is valid and should be present
            # Check specifically for routes that would come from invalid ROUTES_JSON
            ROUTES_FROM_JSON_FOUND=0
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols static route 10.0.0.0/8"; then
                echo "[FAIL] Static route 10.0.0.0/8 should not be generated (malformed ROUTES_JSON)"
                VALIDATION_FAILED=1
                ROUTES_FROM_JSON_FOUND=1
            fi
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols static route 172.16.0.0/12"; then
                echo "[FAIL] Static route 172.16.0.0/12 should not be generated (malformed ROUTES_JSON)"
                VALIDATION_FAILED=1
                ROUTES_FROM_JSON_FOUND=1
            fi
            if [ $ROUTES_FROM_JSON_FOUND -eq 0 ]; then
                echo "[PASS] Static routes from ROUTES_JSON correctly skipped (malformed JSON)"
            fi

            # Default gateway route should still be present (from ETH0_GATEWAY)
            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols static route 0.0.0.0/0 next-hop 192.168.122.1"; then
                echo "[PASS] Default gateway route present (from ETH0_GATEWAY, valid)"
            else
                echo "[FAIL] Default gateway route not present (should be configured from ETH0_GATEWAY)"
                VALIDATION_FAILED=1
            fi

            if $search_cmd "$SERIAL_LOG" | grep -q "VYOS_CMD:.*set protocols ospf"; then
                echo "[FAIL] OSPF commands should not be generated (missing required field)"
                VALIDATION_FAILED=1
            else
                echo "[PASS] OSPF commands correctly skipped (missing required field)"
            fi
            ;;
        ssh-keys)
            assert_command_generated "set system host-name" "Hostname configuration"
            # SSH key configuration commands
            assert_command_generated "set service ssh port 22" "SSH service enabled on port 22"
            assert_command_generated "set system login user vyos authentication public-keys" "SSH public key configuration"
            # Verify key type and key data are configured
            assert_command_generated "authentication public-keys.*type" "SSH key type configured"
            assert_command_generated "authentication public-keys.*key" "SSH key data configured"

            # Verify multiple keys if configured (ssh-keys.env has 2 keys)
            # Count distinct "authentication public-keys <identifier>" entries
            # Extract key identifiers from commands like "set system login user vyos authentication public-keys <id> ..."
            local search_cmd="cat"
            if [ "${SERIAL_LOG_OFFSET:-0}" -gt 0 ]; then
                search_cmd="tail -c +${SERIAL_LOG_OFFSET}"
            fi

            KEY_COUNT=$($search_cmd "$SERIAL_LOG" | grep "VYOS_CMD:.*authentication public-keys" | \
                        sed -n 's/.*authentication public-keys \([^ ]*\).*/\1/p' | \
                        sort -u | wc -l)
            if [ "$KEY_COUNT" -ge 2 ]; then
                echo "[PASS] Multiple SSH keys configured (found $KEY_COUNT distinct keys)"
            elif [ "$KEY_COUNT" -eq 1 ]; then
                echo "[WARN] Only one SSH key found, expected multiple for ssh-keys fixture"
            else
                echo "[FAIL] No SSH keys found in configuration"
                VALIDATION_FAILED=1
            fi
            ;;
        *)
            echo "[WARN] Unknown context '$context_name' - no specific assertions"
            ;;
    esac
}

# Run pytest SSH integration tests
# Arguments:
#   $1 - Repository root path
run_pytest_ssh_tests() {
    local repo_root="$1"

    # Check if SSH is available (should be set by caller)
    if [ "${SSH_AVAILABLE:-0}" -ne 1 ]; then
        echo ""
        echo "[WARN] SSH not available - skipping pytest tests"
        echo "       Shell-based validation passed, marking test as successful"
        return 0
    fi

    echo ""
    echo "=== Pytest SSH Integration Tests ==="
    echo ""

    # Check if pytest is available
    local pytest_cmd
    if command -v pytest >/dev/null 2>&1; then
        pytest_cmd="pytest"
    elif command -v uv >/dev/null 2>&1; then
        pytest_cmd="uv run pytest"
    else
        echo "[WARN] Neither pytest nor uv found - skipping pytest tests"
        echo "       Shell-based validation passed, marking test as successful"
        return 0
    fi

    # Run pytest with integration marker, capturing output
    # The ssh_connection fixture will use the exported SSH_* environment variables
    # Change to repo root to run pytest (tests are at tests/test_ssh_integration.py)
    echo "Running pytest integration tests from $repo_root..."
    cd "$repo_root"
    if $pytest_cmd -m integration tests/test_ssh_integration.py -v; then
        echo ""
        echo "[PASS] Pytest integration tests passed"
        return 0
    else
        echo ""
        echo "[FAIL] Pytest integration tests failed"
        VALIDATION_FAILED=1
        return 1
    fi
}
