# Design: Combine Test Scenarios to Reduce VM Boots

**Issue:** [#123](https://github.com/SouthwestCCDC/vyos-onecontext/issues/123)  
**Status:** Design Phase  
**Author:** AI Assistant  
**Date:** 2026-02-04

## Problem Statement

The integration test suite currently boots a separate QEMU VM for each test fixture, resulting in:
- **12 VM boots** (one per fixture)
- **27-35 minutes** total test time
- **High CI resource usage** (KVM-enabled self-hosted runner)

Each VM boot involves:
1. QEMU startup (~10-15s)
2. VyOS boot process (~30-45s)
3. Contextualization (~5-10s)
4. Test validation (~10-15s)
5. VM shutdown (~5s)

**Total per-fixture time:** ~2-3 minutes

## Goal

Reduce integration test time by grouping related fixtures to run in fewer VM boot cycles.

**Target:** Reduce 12 boots to ~5 boots (~3-5x speedup)

## Proposed Groupings

Based on related functionality:

| Group | Fixtures | Rationale |
|-------|----------|-----------|
| **Basic** | `simple`, `quotes`, `multi-interface` | Basic interface configuration, minimal overlap |
| **Routing** | `static-routes`, `management-vrf`, `ospf` | Routing protocols and VRF |
| **DHCP** | `dhcp` | DHCP server (standalone test) |
| **NAT** | `snat`, `dnat`, `nat-full`, `nat-with-firewall` | NAT scenarios and firewall integration |
| **Complex** | `vrf-with-routing` | Advanced VRF + routing combination |
| **Error Scenarios** | `invalid-json`, `missing-required-fields`, `partial-valid` | Error handling tests |
| **Special** | `start-script`, `ssh-keys` | Special features |

**Note:** Error scenarios and special features could potentially be merged with other groups if isolation isn't critical.

## Design Options

### Option A: Configuration Reset Between Tests (RECOMMENDED)

**Approach:**
1. Boot VM once per group
2. Apply first configuration via contextualization
3. Validate test assertions
4. **Reset configuration state**
5. Apply next configuration
6. Repeat steps 3-5 for all fixtures in group

**Configuration Reset Strategy:**

```bash
# Enter configuration mode
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin

# Delete all configuration nodes (except system basics)
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete protocols
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete nat
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete service dhcp-server
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete vrf

# Commit the reset
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end

# Alternatively: Load minimal config
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper load /config/config.boot.default
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
```

**Pros:**
- Maintains test isolation (each test gets clean state)
- No VM reboot needed (fast)
- Preserves existing fixture files
- Easier to debug (clear separation between tests)

**Cons:**
- Requires careful reset logic to ensure clean state
- Need to verify no state leaks between tests
- More complex test harness

**Implementation:**
- Create `run-qemu-group-test.sh` that:
  - Boots VM once
  - Loops through list of fixtures
  - For each fixture:
    - Applies configuration via SSH (not contextualization ISO)
    - Validates
    - Resets config
- Modify CI to call group test script instead of individual tests

### Option B: Combo Fixtures

**Approach:**
1. Create merged fixture files (e.g., `basic-combo.env`)
2. Apply all configurations in sequence during single boot
3. Validate all scenarios in one test run

**Example combo fixture:**
```bash
# basic-combo.env
HOSTNAME="test-combo-basic"

# Simple test config
ETH0_IP="192.168.122.10"
ETH0_MASK="255.255.255.0"
ETH0_GATEWAY="192.168.122.1"

# Multi-interface test (aliases)
ETH0_ALIAS0_IP="10.0.0.1"
ETH0_ALIAS0_MASK="255.255.255.0"
```

**Pros:**
- Simplest implementation
- Minimal changes to test harness
- Uses existing contextualization path

**Cons:**
- **Breaks test isolation** (one failure affects all)
- Harder to debug which scenario failed
- Loses granularity in test reporting
- Some scenarios may conflict (can't test both masquerade and static NAT at once)
- Difficult to maintain (duplicate config data)

**Verdict:** Not recommended for this use case

### Option C: Dynamic ISO Mounting

**Approach:**
1. Boot VM once
2. Use QEMU monitor to dynamically mount/unmount context ISOs
3. Trigger re-contextualization for each fixture

**Pros:**
- Maintains separate fixture files
- Uses existing contextualization mechanism

**Cons:**
- **Highly complex** implementation
- QEMU ISO hot-swap is not standard practice
- VyOS contextualization runs at boot, not on-demand
- Would need to modify vyos-onecontext to support re-triggering
- Fragile and hard to debug

**Verdict:** Not feasible without major changes to both test harness and vyos-onecontext

## Recommended Approach: Option A (Config Reset)

### Implementation Plan

#### Phase 1: Prototype with Basic Group

1. Create `tests/integration/run-qemu-group-test.sh`:
   - Accept group name and list of fixtures
   - Boot VM once
   - Iterate through fixtures:
     - Generate config commands from fixture context
     - Apply via SSH using `vyatta-cfg-cmd-wrapper`
     - Run validation assertions
     - Reset config state
     - Log results per-fixture

2. Create helper script `tests/integration/reset-vyos-config.sh`:
   - SSH into running VM
   - Delete all user-configured nodes
   - Commit changes
   - Verify clean state

3. Create helper script `tests/integration/apply-context-commands.sh`:
   - Read fixture .env file
   - Parse context variables
   - Call vyos-onecontext parser directly or generate commands
   - Apply via SSH

4. Test with Basic group (`simple`, `quotes`, `multi-interface`):
   - Verify all tests pass
   - Verify no state leakage
   - Measure time savings

#### Phase 2: Extend to All Groups

1. Create group definitions in `run-all-tests.sh` or new config file
2. Add group mode to `run-all-tests.sh`:
   - `--mode=individual` (current behavior, default)
   - `--mode=grouped` (new behavior)
3. Update CI workflow to use grouped mode
4. Measure total time savings

#### Phase 3: Handle Edge Cases

1. **Error scenarios**: These expect contextualization to fail. Either:
   - Keep as individual tests (3 extra boots acceptable)
   - Or run in separate "error group" with special handling

2. **START_SCRIPT tests**: These run commands after commit. Need to ensure script state doesn't leak.

3. **SSH key tests**: These modify authentication. Run early in group or in separate group.

### Validation Requirements

For each test in a group:
1. **Pre-test state verification**:
   - No interfaces configured (except eth0 with DHCP)
   - No routing protocols
   - No NAT rules
   - No DHCP server config
   - Clean firewall state

2. **Post-test validation**:
   - All assertions from original test pass
   - Test artifacts logged separately

3. **Reset verification**:
   - Confirm config nodes deleted
   - No orphaned processes (OSPF, DHCP)
   - Interface state clean

### Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Config state leaks between tests | Implement comprehensive reset verification |
| Harder to debug failures | Log each test separately, include state snapshots |
| Test timeout issues | Set per-fixture timeout, allow group to continue on failure |
| VyOS process state leaks | Monitor process list, kill orphaned daemons if needed |

## Expected Time Savings

### Current Performance
- 12 fixtures × 2.5 min avg = **30 minutes**

### After Optimization
Assuming 5 groups:
- 5 VM boots × 1 min = **5 minutes** (boot overhead)
- 12 tests × 0.5 min = **6 minutes** (test execution, no boot)
- **Total: ~11 minutes**

**Speedup: 2.7x (30 min → 11 min)**

*Note: Actual speedup depends on config reset time and test complexity.*

## Acceptance Criteria

- [ ] Basic group prototype implemented and tested
- [ ] All fixtures pass in grouped mode
- [ ] No test isolation failures observed
- [ ] Time measurement shows >2x speedup
- [ ] CI workflow updated to use grouped mode
- [ ] Documentation updated (testing guide, CI docs)
- [ ] Fallback to individual mode available if needed

## Future Enhancements

1. **Parallel group execution**: If multiple KVM-enabled runners available, run groups in parallel
2. **Smart reset**: Only reset affected config areas instead of full wipe
3. **Snapshot/restore**: Use QEMU snapshots for faster reset (experimental)

## References

- [Issue #123](https://github.com/SouthwestCCDC/vyos-onecontext/issues/123) - Original request
- [Issue #120](https://github.com/SouthwestCCDC/vyos-onecontext/issues/120) - Selective testing (implemented)
- VyOS documentation: Configuration mode and commit behavior

---

*Generated with Claude Sonnet 4.5*
