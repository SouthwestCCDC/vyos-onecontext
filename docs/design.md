# VyOS Sagitta Contextualization: Design Document

## Overview

This document describes the design for VyOS Sagitta (1.4.x) contextualization scripts
used with OpenNebula. These scripts configure VyOS routers at boot time based on
context variables provided by OpenNebula.

## Goals

1. **Stateless configuration**: Router configuration derived entirely from context on every boot
2. **OpenNebula compatibility**: Support standard ONE network context variables
3. **Extensibility**: JSON-based schema for advanced features
4. **Testability**: Python implementation with comprehensive unit tests
5. **Validation**: Catch configuration errors before applying to VyOS

## Architecture

### Hybrid Approach: Shell + Python

```
Boot Sequence:
┌──────────────────────────────────────────────────────────────────────┐
│ VyOS Boot                                                            │
│   └─> /config/scripts/vyos-postconfig-bootup.script (shell)          │
│         ├─> Mount context CD (/dev/sr0 -> /mnt)                      │
│         ├─> Call: /opt/vyos-onecontext/venv/bin/python               │
│         │         -m vyos_onecontext /mnt/context.sh                 │
│         │     ├─> Parse /mnt/context.sh                              │
│         │     ├─> Validate context (Pydantic models)                 │
│         │     ├─> Generate VyOS commands                             │
│         │     └─> Execute via vyatta-cfg-cmd-wrapper                 │
│         └─> Unmount context CD                                       │
└──────────────────────────────────────────────────────────────────────┘
```

**Why hybrid?**

- **Shell boot hook**: Simple, reliable, handles mount/unmount
- **Python in isolated venv**: Type-safe parsing, Pydantic validation, testability
- **No system Python pollution**: Dependencies isolated from VyOS internals

### Component Responsibilities

| Component | Language | Responsibility |
|-----------|----------|----------------|
| `vyos-postconfig-bootup.script` | Shell | Mount context CD, invoke venv Python, unmount |
| `vyos_onecontext/` | Python | Parse context, validate, generate commands |
| `vyos_onecontext/wrapper.py` | Python | Execute VyOS CLI commands via wrapper |

## Context Variable Strategy

### OpenNebula Compatibility

We support standard OpenNebula context variables for basic networking:

```bash
# Standard ONE network variables (per-interface)
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_GATEWAY="10.0.1.254"
ETH0_DNS="8.8.8.8"
ETH0_MTU="1500"

# ONE vrouter management interface
ETH0_VROUTER_MANAGEMENT="YES"

# ONE NIC alias variables (secondary IPs on same interface)
ETH0_ALIAS0_IP="10.0.1.2"
ETH0_ALIAS0_MASK="255.255.255.0"

# Standard ONE identity
HOSTNAME="router-01"
SSH_PUBLIC_KEY="ssh-rsa AAAA... user@host"
```

This provides compatibility with OpenNebula's network contextualization and vrouter conventions.

### NIC Aliases (Secondary IPs)

OpenNebula supports NIC aliases for assigning multiple IPs to a single interface. This is used
for 1:1 NAT scenarios where the router needs additional public IPs.

**How it works:**

1. Terraform declares `nic_alias` blocks referencing a parent NIC
2. OpenNebula manages the IP lease from the virtual network
3. Context receives `ETH{n}_ALIAS{m}_IP`, `ETH{n}_ALIAS{m}_MASK`, etc.
4. Contextualization adds secondary addresses to the interface
5. NAT rules can reference these alias IPs for bidirectional NAT

**Terraform example:**

```hcl
nic {
  name       = "wan"
  network_id = var.wan_network_id
  ip         = "129.244.246.64"
}

nic_alias {
  parent     = "wan"
  network_id = var.wan_network_id
  ip         = "129.244.246.66"  # ONE manages this lease
}
```

**Context variables:**

```bash
ETH0_IP="129.244.246.64"
ETH0_MASK="255.255.255.0"
ETH0_ALIAS0_IP="129.244.246.66"
ETH0_ALIAS0_MASK="255.255.255.0"
```

**Note:** There is a known OpenNebula bug where `ETH{n}_ALIAS{m}_MASK` may be empty. The
contextualization script falls back to the parent interface's mask when this occurs.

### JSON Extensions

For advanced features beyond ONE's standard variables, we use JSON-encoded context variables:

```bash
# JSON-encoded advanced configuration
ROUTES_JSON='{"static":[{"interface":"eth1","destination":"0.0.0.0/0","gateway":"10.63.255.1"}]}'
OSPF_JSON='{"enabled":true,"areas":[{"id":"0.0.0.0","networks":["10.0.0.0/8"]}]}'
```

**Why JSON?**

- Self-documenting field names (vs positional space-delimited)
- Native parsing in Python (`json.loads()`)
- Terraform's `jsonencode()` provides structure validation
- Handles complex nested configuration cleanly

### Escape Hatches

For configuration not covered by structured variables:

```bash
# Raw VyOS commands (one per line)
START_CONFIG="set system option performance throughput"

# Shell script executed after VyOS config commit
START_SCRIPT="#!/bin/bash\necho 'Custom setup'"
```

## Feature Scope

### v1 Features (In Scope)

| Feature | Context Source | Status |
|---------|----------------|--------|
| Interface configuration | `ETHx_IP`, `ETHx_MASK`, etc. | Designed |
| Management VRF | `ETHx_VROUTER_MANAGEMENT` | Designed |
| Hostname | `HOSTNAME` | Designed |
| SSH keys | `SSH_PUBLIC_KEY` | Designed |
| Static routes | `ROUTES_JSON` | Designed |
| OSPF | `OSPF_JSON` | Designed |
| DHCP server | `DHCP_JSON` | Designed |
| Source NAT (masquerade) | `NAT_JSON` | Designed |
| Destination NAT (port forwards) | `NAT_JSON` | Designed |
| 1:1 NAT (bidirectional) | `NAT_JSON` + `ETHx_ALIASy_IP` | Designed |
| Custom commands | `START_CONFIG` | Designed |
| Custom scripts | `START_SCRIPT` | Designed |
| Zone-based firewall | `FIREWALL_JSON` | Designed |

### Out of Scope

| Feature | Reason |
|---------|--------|
| VLAN-tagged interfaces | OpenNebula provides virtual NICs; no qinq support |
| VPN (WireGuard/OpenVPN) | Handled by dedicated VPN infrastructure |
| Captive portal | Not needed; guest access handled differently |
| Schedule-based rules | Complexity not justified for current use cases |
| Scoring relay NAT | Requires VRF + policy routing redesign |
| HA (keepalived/VRRP) | Future enhancement if needed |
| IPv6 | Not currently used in infrastructure |

## Management VRF

Interfaces marked with `ETHx_VROUTER_MANAGEMENT="YES"` are placed in a management VRF
for out-of-band network isolation.

**Behavior:**

- Management interfaces use VRF `management` (routing table 100)
- SSH service binds to management VRF
- Multiple interfaces can be in management VRF (valid for redundancy)
- If no management interface specified, SSH is globally accessible

```python
# Example: Finding management interfaces
mgmt_interfaces = [
    iface for iface in interfaces
    if context.get(f"{iface.upper()}_VROUTER_MANAGEMENT") == "YES"
]
```

## Validation

Pydantic models provide automatic validation with clear error messages:

```python
from pydantic import BaseModel, field_validator
from ipaddress import ip_network, ip_address

class Route(BaseModel):
    interface: str
    destination: str
    gateway: str | None = None
    distance: int = 1
    vrf: str | None = None

    @field_validator('destination')
    @classmethod
    def validate_destination(cls, v: str) -> str:
        ip_network(v, strict=False)  # Raises ValueError if invalid
        return v

    @field_validator('gateway')
    @classmethod
    def validate_gateway(cls, v: str | None) -> str | None:
        if v is not None:
            ip_address(v)  # Raises ValueError if invalid
        return v
```

**Validation types:**

| Validation | How |
|------------|-----|
| IP address format | `ipaddress.ip_address()` in field validator |
| CIDR notation | `ipaddress.ip_network()` in field validator |
| Required fields | Pydantic enforces non-optional fields |
| Type coercion | Pydantic handles string-to-int, etc. |
| Nested objects | Pydantic validates recursively |

**Error handling:**

Validation errors are logged with context and cause contextualization to fail fast,
rather than producing cryptic errors at VyOS commit time:

```
ERROR: Validation failed for ROUTES_JSON:
  static.0.destination: '10.0.0.0/33' is not a valid CIDR network
  static.1.gateway: 'not-an-ip' is not a valid IPv4 address
```

## VyOS Command Execution

Commands are executed through VyOS's configuration wrapper:

```python
WRAPPER = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"

def execute_commands(commands: list[str]) -> None:
    subprocess.run([WRAPPER, "begin"], check=True)
    try:
        for cmd in commands:
            subprocess.run([WRAPPER] + cmd.split(), check=True)
        subprocess.run([WRAPPER, "commit"], check=True)
    finally:
        subprocess.run([WRAPPER, "end"], check=True)
```

All commands are executed within a single transaction. If any command fails,
the entire configuration is rolled back.

## Testing Strategy

### Unit Tests (No VyOS Required)

The Python implementation separates parsing/generation from execution:

```python
import pytest
from vyos_onecontext.models import Route, RoutesConfig
from vyos_onecontext.generators.routing import generate_route_commands

def test_parse_routes():
    """Test JSON parsing into Pydantic models."""
    json_data = '{"static":[{"interface":"eth1","destination":"0.0.0.0/0","gateway":"10.1.1.1"}]}'
    config = RoutesConfig.model_validate_json(json_data)

    assert len(config.static) == 1
    assert config.static[0].interface == "eth1"
    assert config.static[0].destination == "0.0.0.0/0"
    assert config.static[0].gateway == "10.1.1.1"

def test_route_validation_rejects_invalid_cidr():
    """Test that invalid CIDR is rejected."""
    with pytest.raises(ValueError, match="not a valid"):
        Route(interface="eth1", destination="10.0.0.0/33", gateway="10.1.1.1")

def test_generate_route_commands():
    """Test VyOS command generation."""
    route = Route(interface="eth1", destination="0.0.0.0/0", gateway="10.1.1.1")
    commands = generate_route_commands([route])

    assert "set protocols static route 0.0.0.0/0 next-hop 10.1.1.1" in commands
```

### Test Fixtures

Common fixtures in `conftest.py`:

```python
import pytest

@pytest.fixture
def sample_context() -> dict[str, str]:
    """Minimal valid context for testing."""
    return {
        "HOSTNAME": "test-router",
        "ETH0_IP": "10.0.1.1",
        "ETH0_MASK": "255.255.255.0",
        "ETH0_VROUTER_MANAGEMENT": "YES",
    }

@pytest.fixture
def full_context(sample_context) -> dict[str, str]:
    """Full context with all JSON extensions."""
    return {
        **sample_context,
        "ROUTES_JSON": '{"static":[{"interface":"eth1","destination":"0.0.0.0/0","gateway":"10.0.1.254"}]}',
        "OSPF_JSON": '{"enabled":true,"areas":[{"id":"0.0.0.0","networks":["10.0.0.0/8"]}]}',
    }
```

### Integration Tests (VyOS VM)

Full integration tests run in a VyOS VM with mock context:

1. Create context ISO with test variables
2. Boot VyOS VM with context attached
3. Verify resulting configuration matches expected

These are marked with `@pytest.mark.integration` and skipped in normal CI runs.

## Directory Structure

Following the standard uv/hatchling project layout used across SWCCDC Python projects:

```
vyos-onecontext/
├── pyproject.toml                # Project metadata, dependencies, tool config
├── uv.lock                       # Pinned dependencies (generated)
├── justfile                      # Task automation (test, lint, fmt)
├── README.md
├── docs/
│   ├── design.md                 # This document
│   └── context-reference.md      # Context variable reference
├── src/
│   └── vyos_onecontext/
│       ├── __init__.py
│       ├── __main__.py           # Entry point (python -m vyos_onecontext)
│       ├── context.py            # Context parsing
│       ├── models.py             # Pydantic models for config objects
│       ├── generators/
│       │   ├── __init__.py
│       │   ├── interfaces.py     # Interface config generation
│       │   ├── routing.py        # Static routes + OSPF
│       │   ├── services.py       # DHCP, SSH
│       │   └── nat.py            # NAT rules
│       └── wrapper.py            # VyOS CLI wrapper
├── tests/
│   ├── conftest.py               # Shared pytest fixtures
│   ├── unit/
│   │   ├── test_context.py
│   │   ├── test_validators.py
│   │   └── test_generators/
│   │       ├── test_interfaces.py
│   │       ├── test_routing.py
│   │       └── ...
│   └── integration/              # Tests requiring VyOS (future)
│       └── conftest.py
├── scripts/
│   └── vyos-postconfig-bootup.script  # Shell boot hook (installed to VyOS)
└── .github/
    └── ...                       # CI workflows
```

## Runtime Considerations

### Development Environment

Standard uv workflow:

```bash
uv sync                    # Install dependencies
uv run pytest              # Run tests
uv run ruff check .        # Lint
uv build                   # Build wheel for deployment
```

### VyOS Runtime

The Python code runs on VyOS at boot time in an **isolated virtualenv** to avoid
conflicts with VyOS's system Python packages.

**Installation layout on VyOS:**

```
/opt/vyos-onecontext/
└── venv/
    ├── bin/
    │   └── python          # Isolated Python interpreter
    └── lib/
        └── python3.x/
            └── site-packages/
                ├── vyos_onecontext/
                └── pydantic/
```

**Dependencies:**

- `pydantic` - Data validation and settings management
- Standard library: `ipaddress`, `json`, `subprocess`, `logging`

### Packer Build Process

The virtualenv is created during image build:

```hcl
# 1. Copy the wheel built by CI
provisioner "file" {
  source      = "dist/vyos_onecontext-${var.version}-py3-none-any.whl"
  destination = "/tmp/vyos_onecontext.whl"
}

# 2. Create isolated venv and install
provisioner "shell" {
  inline = [
    "python3 -m venv /opt/vyos-onecontext/venv",
    "/opt/vyos-onecontext/venv/bin/pip install --no-cache-dir /tmp/vyos_onecontext.whl",
    "rm /tmp/vyos_onecontext.whl"
  ]
}

# 3. Install boot hook
provisioner "file" {
  source      = "scripts/vyos-postconfig-bootup.script"
  destination = "/tmp/vyos-postconfig-bootup.script"
}

provisioner "shell" {
  inline = [
    "mv /tmp/vyos-postconfig-bootup.script /config/scripts/",
    "chmod 755 /config/scripts/vyos-postconfig-bootup.script"
  ]
}
```

### Boot Script

The shell boot hook invokes the venv Python:

```bash
#!/bin/sh
# Mount OpenNebula context CD
mount -t iso9660 /dev/sr0 /mnt 2>/dev/null

if [ $? -eq 0 ]; then
    # Run contextualization from isolated venv
    /opt/vyos-onecontext/venv/bin/python -m vyos_onecontext /mnt/context.sh
    umount /mnt
fi
```

### Benefits of Isolated Venv

| Benefit | Description |
|---------|-------------|
| No conflicts | VyOS system packages remain untouched |
| Pydantic validation | Clean data validation with good error messages |
| Reproducible | Same wheel + dependencies every build |
| Testable | Exact same code runs in dev and production |

## Sagitta Syntax Notes

VyOS 1.4 (Sagitta) has syntax changes from 1.3 (Equuleus):

| Feature | Equuleus | Sagitta |
|---------|----------|---------|
| NAT interface | `outbound-interface eth0` | `outbound-interface name 'eth0'` |
| Static route | `set protocols static interface-route ...` | `set protocols static route X interface Y` |
| Firewall zones | `zone-policy zone` | `firewall zone` |
| OSPF network | `area X network Y` | `area X network Y` (unchanged) |

The generators produce Sagitta-compatible syntax.

## Firewall Design

VyOS Sagitta uses nftables and supports zone-based firewalling. Our contextualization
uses zones for coarse inter-network policy while leaving management VRF unfiltered.

### Architecture

**Zone-based approach:**
- Zones group interfaces by security level
- Each zone has a `default_action` (drop or reject)
- Policies define allowed traffic between zone pairs
- Rules within policies can filter by address, port, protocol

**Key behaviors:**
- NAT (DNAT) happens before firewall → rules match post-NAT (internal) addresses
- Global state policies handle established/related/invalid traffic
- Interfaces not in any zone bypass zone filtering entirely
- Warning emitted for unzoned interfaces (intentional for management VRF)

### Interaction with VRF

There is a known VyOS bug (T2251) where zone-based firewall + VRF has issues with
interface detection. Our approach avoids this by:

1. Leaving management VRF interfaces out of zones entirely
2. Management traffic flows freely (no zone filtering)
3. Only non-VRF interfaces participate in zone-based filtering

This sidesteps the bug and matches the intent of keeping management open.

### Packet Flow

```
Inbound packet arrives
    │
    ▼
┌─────────────────┐
│   Prerouting    │ ◄── DNAT (port forwards, 1:1 NAT) happens here
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Routing decision│
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐  ┌───────┐
│ Input │  │Forward│ ◄── Zone policies evaluate here (post-NAT addresses)
│(local)│  │(transit)│
└───────┘  └───┬───┘
               │
               ▼
┌─────────────────┐
│   Postrouting   │ ◄── SNAT (masquerade, 1:1 outbound) happens here
└─────────────────┘
```

### Rule Granularity

Within a zone-to-zone policy, rules can have varying specificity:

| Pattern | Source | Destination | Use Case |
|---------|--------|-------------|----------|
| zone-to-zone | (any) | (any) | GAME can reach SCORING on web ports |
| zone-to-host | (any) | specific IP/group | GAME can reach scoring engine |
| host-to-zone | specific IP/group | (any) | Red team server can reach GAME |
| host-to-host | specific IP/group | specific IP/group | Admin host can SSH to specific server |

### Rule Auto-Numbering

The generator auto-numbers rules starting at 100, incrementing by 100 (100, 200, 300...).

This leaves room for operators to inject manual rules via `START_CONFIG`:
- Rules 1-99: Reserved for manual "early" rules (highest priority)
- Rules 100+: Auto-generated from FIREWALL_JSON
- Rules 900+: Reserved for manual "late" rules (before default-action)

**TODO:** Finalize numbering scheme during implementation. Consider whether to expose
rule priority in the JSON schema or keep it implicit.

### Generated Configuration

The generator produces:

1. **Global state policies:**
```
set firewall global-options state-policy established action accept
set firewall global-options state-policy related action accept
set firewall global-options state-policy invalid action drop
```

2. **Firewall groups:**
```
set firewall group network-group GAME network '10.64.0.0/10'
set firewall group port-group WEB port 80
set firewall group port-group WEB port 443
```

3. **Zone definitions:**
```
set firewall zone WAN interface eth0
set firewall zone WAN default-action drop
set firewall zone GAME interface eth1
set firewall zone GAME default-action drop
```

4. **Named rulesets and zone policies:**
```
set firewall ipv4 name WAN-to-GAME default-action drop
set firewall ipv4 name WAN-to-GAME rule 100 action accept
set firewall ipv4 name WAN-to-GAME rule 100 destination group network-group SCORING_ENGINE
set firewall ipv4 name WAN-to-GAME rule 100 description "NAT'd traffic to scoring"

set firewall zone GAME from WAN firewall name WAN-to-GAME
```

### Future Enhancements

These items are not in v1 scope but are documented for future consideration:

1. **LOCAL zone support**: Traffic to/from the router itself (SSH, OSPF, BGP, DNS services).
   Currently, services on the router are accessible if the interface is unzoned (management VRF)
   or via global state policies for return traffic. Explicit LOCAL zone policies may be needed
   for more complex setups.

2. **Rule logging**: VyOS supports per-rule logging with configurable prefixes. Could add
   `log: true` and `log_prefix: "..."` fields to rule schema.

3. **Interface groups in rules**: VyOS allows matching interface-groups directly in rules
   (not just in zones). Could add `source_interface_group` / `destination_interface_group`.

## Related Documentation

**Project documentation (mkdocs site):**

- [VyOS Router v3 Project](../../../../docs/docs/projects/backlog/vyos-router-v3/index.md) - Project overview and status
- [Requirements](../../../../docs/docs/projects/backlog/vyos-router-v3/requirements.md) - Detailed requirements analysis
- [Implementation Plan](../../../../docs/docs/projects/backlog/vyos-router-v3/implementation-plan.md) - Phased implementation approach

**Technical reference:**

- [Context Variable Reference](context-reference.md) - Complete schema for all context variables

**Current production (Equuleus):**

- [VyOS Operator Guide](../../../../docs/docs/network/vyos_operator_guide.md) - Current Equuleus deployment guide
- [VyOS Developer Guide](../../../../docs/docs/network/vyos_developer_guide.md) - Current Equuleus build pipeline

**External:**

- [VyOS 1.4 Documentation](https://docs.vyos.io/en/sagitta/)
- [OpenNebula Contextualization](https://docs.opennebula.io/6.8/management_and_operations/references/template.html#context-section)
- [VyOS Cloud-Init](https://docs.vyos.io/en/sagitta/automation/cloud-init.html)
