# Integration Tests

End-to-end integration tests for VyOS contextualization using QEMU.

## Overview

These tests boot a VyOS image in QEMU with test context and validate that
contextualization works correctly. This catches integration issues that unit
tests miss (like the quote bug in #40).

## Requirements

- **VyOS image**: A VyOS Sagitta (1.4.x) qcow2 image with vyos-onecontext installed
- **QEMU/KVM**: For running the VM
- **genisoimage or mkisofs**: For creating context ISOs
- **sshpass**: Required for SSH-based validation

On Ubuntu/Debian:
```bash
sudo apt-get install qemu-system-x86 qemu-kvm genisoimage sshpass
```

## Running Tests Locally

1. **Build a VyOS Image**

   You need a VyOS image with vyos-onecontext pre-installed. This is typically
   built using Packer in the `deployment` repository.

2. **Run a Single Test**

   ```bash
   # Create a context ISO
   ./tests/integration/create-test-iso.sh test-context.iso tests/integration/contexts/simple.env

   # Run the test
   ./tests/integration/run-qemu-test.sh /path/to/vyos-image.qcow2 test-context.iso
   ```

3. **Run All Tests**

   ```bash
   # Run all test fixtures
   ./tests/integration/run-all-tests.sh /path/to/vyos-image.qcow2

   # Run specific fixtures only
   ./tests/integration/run-all-tests.sh /path/to/vyos-image.qcow2 simple dhcp nat-full
   ```

## Test Contexts

Test context files are in `contexts/`:

- **simple.env**: Basic single-interface router
- **quotes.env**: Regression test for quote bug (#40)
- **multi-interface.env**: Multi-interface router with alias IPs
- **management-vrf.env**: Management VRF configuration
- **static-routes.env**: Static routing configuration
- **ospf.env**: OSPF dynamic routing
- **dhcp.env**: DHCP server configuration
- **snat.env**: Source NAT (masquerade)
- **dnat.env**: Destination NAT (port forwarding)
- **nat-full.env**: Full NAT suite (SNAT + DNAT + binat)
- **vrf-with-routing.env**: VRF with static routes and OSPF
- **nat-with-firewall.env**: NAT with zone-based firewall
- **start-script.env**: START_SCRIPT post-configuration script execution

### Error Scenarios

Error scenario fixtures test graceful error handling:

- **invalid-json.env**: Malformed JSON in ROUTES_JSON (tests JSON parse error handling)
- **missing-required-fields.env**: OSPF_JSON missing required 'enabled' field (tests Pydantic validation)
- **partial-valid.env**: Multiple errors across different sections (tests error accumulation)

These scenarios validate that:
- Valid configuration sections are still applied when other sections fail
- Errors are collected and logged with clear messages
- An ERROR SUMMARY is generated
- Exit code 1 is returned (indicating errors) but boot completes successfully

## CI Integration

In CI, these tests run on self-hosted KVM runners with selective testing based on
changed files:

- **On pull requests**: Only affected test fixtures are run based on which source
  files changed (see `.github/test-mapping.yml` for the mapping)
- **On push to sagitta**: All test fixtures run to ensure comprehensive coverage

This selective testing approach reduces CI time for typical PRs from 25-30 minutes
to 2-6 minutes, while maintaining full coverage on the main branch.

### How Selective Testing Works

1. The `.github/scripts/select-fixtures.py` script compares changed files against
   the mapping in `.github/test-mapping.yml`
2. Each source file pattern maps to one or more test fixtures
3. Core files (parser, models, wrapper) trigger all fixtures
4. Generator files trigger only their relevant fixtures (e.g., `nat.py` → NAT fixtures)
5. If no patterns match, all fixtures run (fail-safe)

### Manual Fixture Selection

You can run specific fixtures locally for faster iteration:

```bash
# Run only NAT-related tests
./tests/integration/run-all-tests.sh vyos-image.qcow2 snat dnat nat-full

# Run only interface and VRF tests
./tests/integration/run-all-tests.sh vyos-image.qcow2 simple multi-interface management-vrf
```

## How It Works

1. **create-test-iso.sh**: Creates an ISO with context.sh from a test context file
2. **run-qemu-test.sh**: Boots VyOS in QEMU with the context ISO attached
3. The VM boots and runs the vyos-onecontext boot script (triggered via udev when the context CD is mounted)
4. The script waits for SSH to become available (using test SSH key)
5. The script validates contextualization by checking serial log output and optionally via SSH

## Validation

The test script checks:

- Contextualization script executed
- No errors in contextualization output
- No Python exceptions in logs
- Successful completion message in logs
- SSH connectivity is established (using default VyOS credentials)

### SSH Infrastructure

The integration test harness includes SSH connectivity for functional validation:

- **Password authentication**: Uses default VyOS credentials (vyos/vyos) for SSH access
  - Note: Earlier designs considered SSH key-based authentication, but the final
    implementation uses password auth for simplicity and compatibility with stock VyOS images
- **SSH port forwarding**: Port 10022 on host forwards to port 22 in VM
- **SSH connection retry**: Waits up to 60 seconds for SSH to become ready after boot
- **Helper function**: `ssh_command()` is exported for running commands on the VM

#### SSH-based pytest tests

The SSH infrastructure is available to pytest tests when running in the QEMU harness via
the `ssh_connection` fixture (defined in `tests/conftest.py`).

**Example pytest integration test:**

```python
@pytest.mark.integration
def test_hostname_configured(ssh_connection):
    output = ssh_connection("show configuration | grep 'host-name'")
    assert "test-" in output
```

These tests are automatically skipped when running pytest normally (outside the QEMU harness).

## Debugging Failed Tests

When a test fails, the script prints the full serial log. You can also:

1. Run QEMU manually with the test ISO:
```bash
./tests/integration/create-test-iso.sh test.iso tests/integration/contexts/simple.env

qemu-system-x86_64 \
  -enable-kvm \
  -m 2048 \
  -drive file=/path/to/vyos-image.qcow2,format=qcow2,if=virtio,snapshot=on \
  -cdrom test.iso \
  -nographic
```

2. Log in (vyos/vyos) and check:
```
show configuration
show log
```

## Writing New Tests

To add a new test scenario:

1. Create a new context file in `contexts/`
2. Run with `create-test-iso.sh` and `run-qemu-test.sh`
3. The validation is automatic via serial log checking

For custom validation, modify `run-qemu-test.sh` to check specific
configuration elements.

### Validating New Fixtures Before Merge

**IMPORTANT**: New test fixtures MUST be validated before adding them to the
`TEST_SCENARIOS` array in `run-all-tests.sh` and merging.

With selective testing enabled (see CI Integration above), new fixtures may not
run during PR CI if they're not mapped to changed code paths in
`.github/test-mapping.yml`. This means a new fixture could be added to the repo
but never actually execute until after merge, potentially introducing broken tests.

**Before merging a PR that adds a new test fixture:**

1. **Run the fixture locally** using the steps in "Running Tests Locally" above, OR
2. **Add the fixture to test-mapping.yml** for the relevant code paths it exercises,
   ensuring it runs during PR CI

This validation requirement was added after PR #125 introduced `start-script.env`,
which was added to `TEST_SCENARIOS` but never ran until post-merge, where it failed.
