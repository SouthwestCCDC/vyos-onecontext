# Group Testing for Integration Tests

This directory contains experimental support for running multiple test fixtures in a single VM boot cycle to reduce overall test time.

## Motivation

The standard integration test approach boots a separate QEMU VM for each fixture:
- **12 fixtures** × **~2.5 minutes per boot** = **~30 minutes total**

Group testing boots one VM per test group and applies multiple configurations:
- **~5 groups** × **~2 minutes** = **~10 minutes total**
- **Speedup: 3x faster**

See [Design Document](../../docs/optimization/combine-test-scenarios-design.md) for full details.

## How It Works

1. **Boot VM once** with minimal bootstrap configuration
2. **Apply first test** configuration via SSH using vyos-onecontext
3. **Validate** test assertions
4. **Reset configuration** to clean state
5. **Repeat steps 2-4** for remaining tests in group

## Scripts

### Core Scripts

- `run-qemu-group-test.sh` - Main group test runner
- `apply-context-via-ssh.sh` - Apply context configuration to running VM
- `reset-vyos-config.sh` - Reset VyOS config to clean state between tests

### Test Scripts

- `test-basic-group.sh` - Run the "basic" group prototype (simple, quotes, multi-interface)

## Usage

### Running a Group Test

```bash
# Test the basic group (prototype)
./test-basic-group.sh /path/to/vyos-onecontext-test.qcow2

# Or run a custom group
./run-qemu-group-test.sh /path/to/vyos.qcow2 mygroup fixture1 fixture2 fixture3
```

### Example: Basic Group

```bash
cd tests/integration
./test-basic-group.sh ../../packer/output/vyos-onecontext-test.qcow2
```

Expected output:
```
========================================
  VyOS Group Integration Test
========================================
Image: vyos-onecontext-test.qcow2
Group: basic
Fixtures: simple quotes multi-interface

[... VM boot and SSH setup ...]

========================================
Test 1/3: simple
========================================
Applying configuration...
[PASS] Configuration applied

Resetting configuration for next test...
[PASS] Configuration reset

========================================
Test 2/3: quotes
========================================
[... similar output ...]

========================================
  Group Test Results: basic
========================================
Total:  3
Passed: 3
Failed: 0

[PASS] All tests in group passed!

========================================
  Performance Results
========================================
Group test time: 180s (3m 0s)

For comparison, individual tests would take:
  3 fixtures × ~150s = ~450s (7m 30s)

Speedup: 2.5x faster
[SUCCESS] Group testing is significantly faster!
```

## Test Isolation

Each test gets a clean configuration state:

**Between tests:**
1. All user-configured sections are deleted (interfaces, protocols, NAT, etc.)
2. System basics are preserved (SSH, default credentials)
3. Configuration is committed
4. Next test starts with clean slate

**What's preserved:**
- SSH access (eth0 with connectivity)
- System login credentials (vyos/vyos)
- Base system configuration

**What's reset:**
- Interface IP addresses and VRF assignments
- Routing protocols (static routes, OSPF)
- NAT rules
- DHCP server configuration
- Firewall rules
- VRF definitions

## Current Status

**Phase 1: Prototype (In Progress)**
- [x] Design document created
- [x] Helper scripts implemented
- [x] Basic group test script created
- [ ] Test on actual VyOS image
- [ ] Verify no state leakage
- [ ] Measure actual performance

**Phase 2: Full Implementation (TODO)**
- [ ] Define all test groups
- [ ] Add validation assertions to group tests
- [ ] Update run-all-tests.sh to support grouped mode
- [ ] Update CI workflow

**Phase 3: Production (TODO)**
- [ ] Enable grouped mode by default in CI
- [ ] Update documentation
- [ ] Monitor for issues

## Proposed Groups

| Group | Fixtures | Boot Time |
|-------|----------|-----------|
| **basic** | simple, quotes, multi-interface | ~2min |
| **routing** | static-routes, management-vrf, ospf | ~2min |
| **nat** | snat, dnat, nat-full, nat-with-firewall | ~3min |
| **services** | dhcp, start-script, ssh-keys | ~2min |
| **complex** | vrf-with-routing | ~2min |
| **errors** | invalid-json, missing-required-fields, partial-valid | ~2min |

**Total: ~13 minutes** (vs 30 minutes for individual tests)

## Known Limitations

1. **Test assertions incomplete**: Current prototype only tests configuration application, not full validation
2. **Error scenarios**: Tests that expect contextualization to fail may need special handling
3. **SSH key tests**: Modify authentication - may affect subsequent tests if not reset properly
4. **START_SCRIPT tests**: Execute arbitrary code - need to ensure cleanup

## Debugging

### VM Boot Issues

Check serial log (path is printed at test startup):
```bash
# The serial log is under the per-run temp directory
# Example path: /tmp/tmp.XXXXXX/serial.log
# Look for the "Serial log: /tmp/tmp.XXXXXX/serial.log" line in test output

# Look for contextualization errors
grep "vyos-onecontext" /tmp/tmp.XXXXXX/serial.log

# Check for boot failures
grep "ERROR\|FAIL" /tmp/tmp.XXXXXX/serial.log
```

### SSH Connection Issues

```bash
# Test SSH connectivity manually
sshpass -p vyos ssh -o StrictHostKeyChecking=no \
  -p 10022 vyos@localhost "echo OK"
```

### Configuration Reset Issues

```bash
# Connect to VM and check config
sshpass -p vyos ssh -p 10022 vyos@localhost

# In VyOS shell:
show configuration
show interfaces
show protocols
```

## Troubleshooting

**Problem:** "SSH did not become ready"
- Check if QEMU is running: `ps aux | grep qemu`
- Check serial log for boot errors
- Increase SSH timeout in script

**Problem:** "Configuration reset failed"
- VyOS might be in an inconsistent state
- Check for orphaned processes: `ssh vyos@localhost "ps aux | grep -E 'ospf|dhcp'"`
- May need to restart affected services

**Problem:** "Configuration application failed"
- Check context file syntax
- Verify vyos-onecontext is installed in VM
- Check for Python errors in output

## Next Steps

1. **Test the prototype** on actual VyOS test image
2. **Measure performance** and verify speedup
3. **Add validation** assertions from original tests
4. **Implement all groups** if prototype is successful
5. **Update CI** to use grouped mode

## References

- [Issue #123](https://github.com/SouthwestCCDC/vyos-onecontext/issues/123) - Original request
- [Design Document](../../docs/optimization/combine-test-scenarios-design.md) - Full technical design
- [run-all-tests.sh](run-all-tests.sh) - Current individual test runner

---

**Status:** Prototype - Not yet used in CI  
**Author:** AI Assistant  
**Date:** 2026-02-04
