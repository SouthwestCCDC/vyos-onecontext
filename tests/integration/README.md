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
   ./tests/integration/run-all-tests.sh /path/to/vyos-image.qcow2
   ```

## Test Contexts

Test context files are in `contexts/`:

- **simple.env**: Basic single-interface router
- **quotes.env**: Regression test for quote bug (#40)
- **multi-interface.env**: Multi-interface router setup

## CI Integration

In CI, these tests run on self-hosted KVM runners:

```yaml
jobs:
  integration-test:
    runs-on: [self-hosted, kvm]
    steps:
      - name: Download VyOS image artifact
        # ...
      - name: Run integration tests
        run: ./tests/integration/run-all-tests.sh vyos-image.qcow2
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
- SSH connectivity is attempted (best-effort if test SSH key is available)

### SSH Infrastructure

The integration test harness includes SSH connectivity for functional validation:

- **Password authentication**: Uses default VyOS credentials (vyos/vyos) for SSH access
  - Note: Earlier designs considered SSH key-based authentication, but the final
    implementation uses password auth for simplicity and compatibility with stock VyOS images
- **SSH port forwarding**: Port 10022 on host forwards to port 22 in VM
- **SSH connection retry**: Waits up to 60 seconds for SSH to become ready after boot
- **Helper function**: `ssh_command()` is exported for running commands on the VM

#### SSH-based pytest tests

The SSH infrastructure sets up environment variables that enable pytest-based functional
validation through the `ssh_connection` fixture (defined in `tests/conftest.py`).

**Current status**: These pytest tests exist in `tests/test_ssh_integration.py` but are **not
currently invoked by the CI integration test workflow**. The CI job only runs
`run-all-tests.sh`, which validates via serial log output. Full pytest integration into the
QEMU harness is planned as follow-up work.

**Manual usage**: You can run pytest tests manually after starting the QEMU harness.
The `ssh_connection` fixture requires these environment variables:

- `SSH_AVAILABLE=1` - Enables the SSH fixture (otherwise tests are skipped)
- `SSH_PASSWORD` - SSH password (defaults to `vyos`)
- `SSH_HOST` - SSH hostname (defaults to `localhost`)
- `SSH_PORT` - SSH port (defaults to `10022`)
- `SSH_USER` - SSH username (defaults to `vyos`)

Example:

**Important:** The `run-qemu-test.sh` script runs in a subshell and has an EXIT trap that
kills the QEMU VM when it exits. Variables exported by the script do not persist to the caller.

To run pytest tests manually, you must either:

**Option 1: Manually manage the VM and export variables**

```bash
# Start QEMU manually and keep it running (modify run-qemu-test.sh or run QEMU directly)
# Then export the variables yourself:
export SSH_AVAILABLE=1
export SSH_PASSWORD="vyos"
export SSH_HOST="localhost"
export SSH_PORT="10022"
export SSH_USER="vyos"

# Run pytest with the integration marker
pytest tests/test_ssh_integration.py -v -m integration
```

**Option 2: Modify run-qemu-test.sh to invoke pytest before it exits**

Edit the script to call pytest at the end (before the EXIT trap fires), or remove the
EXIT trap and manage QEMU cleanup manually.

**Example pytest integration test:**

```python
@pytest.mark.integration
def test_hostname_configured(ssh_connection):
    output = ssh_connection("show configuration | grep 'host-name'")
    assert "test-" in output
```

These tests are automatically skipped when running pytest normally (without the SSH environment
variables set by the QEMU harness).

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
