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

## Operational Model

**Stateless by default:** Routers regenerate their entire configuration from context on every
boot. The config is committed but not saved to persistent storage. This ensures routers always
reflect their current context without drift.

**Implications:**
- Manual changes via SSH are lost on reboot
- To change config: update context in Terraform, reboot (or replace VM)
- No incremental updates or config merging
- Generator assumes blank slate every boot

### ONECONTEXT_MODE Variable

The `ONECONTEXT_MODE` context variable controls save behavior at the end of contextualization:

| Value | Behavior | Consistency |
|-------|----------|-------------|
| `stateless` (default) | Don't save. Regenerate fresh every boot. | Guaranteed |
| `save` | Save after commit. Still run onecontext on future boots. | **None** - discouraged |
| `freeze` | Save and disable onecontext hook. Future boots use saved config. | N/A - manual management |

**Completion messages:**

```
stateless: "Configuration applied (stateless mode - not saved)"
save:      "Configuration applied and saved (WARNING: will regenerate from non-fresh state on next boot)"
freeze:    "Configuration applied, saved, and frozen (onecontext disabled for future boots)"
```

**Mode details:**

- **stateless**: Normal operation. Config regenerated from context on every boot. Recommended.
- **save**: Escape hatch only. Saves config but still runs onecontext on future boots. The next
  boot starts from saved state rather than fresh, so context changes may conflict with leftover
  config. No consistency guarantees. Use only if you have a specific need.
- **freeze**: Transitions router to stateful management. Saves config and disables the onecontext
  boot hook. Future boots use the saved config; context is ignored. Once frozen, the operator
  owns consistency.

**Use cases for freeze mode:**
- Complex customizations beyond what context supports
- Handing off to Ansible or other config management
- One-off special-purpose routers

Once frozen, the contextualization system makes no attempt to detect drift or merge with
existing config.

## Architecture

### Hybrid Approach: Shell + Python

```
Boot Sequence:
┌──────────────────────────────────────────────────────────────────────┐
│ VyOS Boot                                                            │
│   └─> /config/scripts/vyos-postconfig-bootup.script (shell)          │
│         ├─> Mount context CD, source variables                       │
│         ├─> Call: /opt/vyos-onecontext/venv/bin/python               │
│         │         -m vyos_onecontext /var/run/one-context/one_env    │
│         │     ├─> Parse context file (shell variable format)         │
│         │     ├─> Validate context (Pydantic models)                 │
│         │     ├─> Cross-reference validation                         │
│         │     ├─> Generate VyOS commands                             │
│         │     └─> Execute via vyatta-cfg-cmd-wrapper                 │
│         └─> Handle post-commit (save/freeze if configured)           │
└──────────────────────────────────────────────────────────────────────┘
```

**Note:** The default context file path is `/var/run/one-context/one_env`, which is where
OpenNebula's standard contextualization scripts store parsed variables. The path can be
overridden via command-line argument for testing.

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
| Interface configuration | `ETHx_IP`, `ETHx_MASK`, etc. | **Implemented** |
| NIC aliases (secondary IPs) | `ETHx_ALIASy_IP`, etc. | **Implemented** |
| MTU configuration | `ETHx_MTU` | **Implemented** |
| Default gateway | `ETHx_GATEWAY` | **Implemented** |
| Hostname | `HOSTNAME` | **Implemented** |
| SSH keys | `SSH_PUBLIC_KEY` | **Implemented** |
| Cross-reference validation | (automatic) | **Implemented** |
| Custom scripts | `START_SCRIPT` | **Implemented** |
| Management VRF | `ETHx_VROUTER_MANAGEMENT` | **Implemented** |
| Static routes | `ROUTES_JSON` | Model ready, generator pending |
| OSPF | `OSPF_JSON` | Model ready, generator pending |
| DHCP server | `DHCP_JSON` | Model ready, generator pending |
| Source NAT (masquerade) | `NAT_JSON` | Model ready, generator pending |
| Destination NAT (port forwards) | `NAT_JSON` | Model ready, generator pending |
| 1:1 NAT (bidirectional) | `NAT_JSON` + `ETHx_ALIASy_IP` | Model ready, generator pending |
| Custom commands | `START_CONFIG` | Parsed, execution pending |
| Zone-based firewall | `FIREWALL_JSON` | Model ready, generator pending |

### Out of Scope (for vrouter-infra)

| Feature | Reason |
|---------|--------|
| VLAN-tagged interfaces | OpenNebula provides virtual NICs; no QinQ support |
| VPN (WireGuard/OpenVPN) | Handled by dedicated VPN infrastructure |
| Captive portal | Not needed; guest access handled differently |
| Schedule-based rules | Complexity not justified for current use cases |
| HA (keepalived/VRRP) | Future enhancement if needed |
| IPv6 | Not currently used in infrastructure |

### vrouter-relay (Separate Design)

The scoring relay role (`vrouter-relay`) requires separate design work and is **not covered by
this document**. Key differences:

- Uses VRF + policy routing for scoring traffic isolation
- Has relay-specific context variables (not the same as vrouter-infra)
- Based on approach from 2025 (old one-context + Ansible combination)
- May share implementation code with vrouter-infra but distinct semantics

See:

- [Relay Requirements](relay-requirements.md) - Detailed requirements for vrouter-relay
- [Project Requirements](../../../../docs/docs/projects/active/vyos-router-v3/requirements.md#3-image-variants-roles) - Role definitions

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

## Default Gateway Selection

The default route (0.0.0.0/0) is automatically generated based on interface gateway settings.

**Selection algorithm:**

1. Sort interfaces by name (natural sort: eth0, eth1, eth2, ..., eth10)
2. Find the first interface where:
   - Interface has `ETHx_GATEWAY` configured
   - Gateway IP differs from interface's own IP (router is not the gateway)
   - Interface is NOT in management VRF
3. Generate `set protocols static route 0.0.0.0/0 next-hop <gateway>`

**Example with 3 interfaces:**

- `eth0`: 10.0.0.1/24, gateway 10.0.0.254 -> **wins** (gateway != interface IP)
- `eth1`: 192.168.1.1/24, gateway 192.168.1.1 -> ignored (router IS the gateway)
- `eth2`: 172.16.0.1/24, no gateway -> ignored

If `eth0` were in management VRF, the main VRF would have no default gateway.

**Why gateway == interface IP is ignored:**

When the router itself is the gateway for a network (common for internal interfaces),
specifying the interface's own IP as the gateway is meaningless. This pattern is detected
and skipped, allowing the true upstream gateway to be selected automatically.

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

### Cross-Reference Validation

Beyond basic field validation, the `RouterConfig` model performs cross-reference validation
to ensure configuration consistency. These validators run after all individual models are
parsed and catch errors that involve multiple configuration sections.

**Implemented validators:**

| Validator | Purpose |
|-----------|---------|
| `validate_nat_interface_references` | NAT rules reference existing interfaces |
| `validate_binat_external_addresses` | Binat external_address exists as IP/alias on interface |
| `validate_dhcp_pool_interfaces` | DHCP pools reference existing interfaces |
| `validate_firewall_zone_interfaces` | Firewall zones reference existing interfaces |
| `validate_ospf_interfaces` | OSPF interface config references existing interfaces |
| `validate_static_route_interfaces` | Static routes reference existing interfaces |
| `validate_alias_parent_interfaces` | Alias parent interfaces exist |

These validators use Pydantic's `@model_validator(mode="after")` to run after all
fields are populated, allowing them to check relationships across the entire config.

**Example error:**

```
ERROR: Validation failed:
  Source NAT rule references non-existent outbound_interface: 'eth5'
  Binat rule external_address '10.0.1.99' is not configured on interface 'eth0'
```

This approach catches configuration mistakes early with clear error messages, rather
than failing cryptically at VyOS commit time or creating broken configurations.

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
│       ├── parser.py             # Context file parsing
│       ├── models/               # Pydantic models (subpackage)
│       │   ├── __init__.py       # Re-exports all models
│       │   ├── config.py         # RouterConfig, OnecontextMode
│       │   ├── interface.py      # InterfaceConfig, AliasConfig
│       │   ├── routing.py        # StaticRoute, OspfConfig
│       │   ├── dhcp.py           # DhcpPool, DhcpReservation
│       │   ├── nat.py            # SourceNatRule, DestNatRule, BinatRule
│       │   └── firewall.py       # FirewallZone, FirewallPolicy, etc.
│       ├── generators/
│       │   ├── __init__.py       # generate_config() entry point
│       │   ├── base.py           # BaseGenerator abstract class
│       │   ├── system.py         # HostnameGenerator, SshKeyGenerator
│       │   └── interface.py      # InterfaceGenerator
│       └── wrapper.py            # VyOS CLI wrapper (VyOSConfigSession)
├── tests/
│   ├── __init__.py
│   ├── fixtures/                 # Sample context files for testing
│   │   ├── simple_router.env
│   │   ├── nat_gateway.env
│   │   └── full_featured.env
│   ├── test_models.py            # Model validation tests
│   ├── test_parser.py            # Context parsing tests
│   ├── test_generators.py        # Command generation tests
│   ├── test_wrapper.py           # VyOS CLI wrapper tests
│   ├── test_main.py              # CLI entry point tests
│   └── test_smoke.py             # End-to-end smoke tests
├── scripts/
│   └── ...                       # Boot hook scripts for VyOS image
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
| OSPF config | `area X network Y` | `interface X area Y` (interface-based, preferred) |
| Passive interface | `passive-interface X` | `interface X passive` |

The generators produce Sagitta-compatible syntax using the interface-based OSPF approach
for clarity and per-interface configuration.

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

**Firewall rules** (per-policy namespace - each zone-pair ruleset has its own numbering):

| Range | Purpose |
|-------|---------|
| 1-99 | Reserved for manual "early" rules via `START_CONFIG` |
| 100, 110, 120... | Auto-generated from FIREWALL_JSON (increment by 10) |
| 9000+ | Reserved for manual "late" rules (before default-action) |

**NAT rules** (global namespace - separate for source and destination NAT):

| Range | Purpose |
|-------|---------|
| 1-99 | Reserved for manual rules via `START_CONFIG` |
| 100, 110, 120... | Auto-generated (increment by 10) |

NAT rule assignment order within the auto-generated range:
- Source NAT: masquerade rules, then binat outbound rules
- Dest NAT: port forwards, then binat inbound rules

Rule priority is implicit based on position in the JSON arrays. The schema does not expose
rule numbers directly - operators who need precise control should use `START_CONFIG`.

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

- [VyOS Router v3 Project](../../../../docs/docs/projects/active/vyos-router-v3/index.md) - Project overview and status
- [Requirements](../../../../docs/docs/projects/active/vyos-router-v3/requirements.md) - Detailed requirements analysis
- [Implementation Plan](../../../../docs/docs/projects/active/vyos-router-v3/implementation-plan.md) - Phased implementation approach

**Technical reference:**

- [Context Variable Reference](context-reference.md) - Complete schema for all context variables

**Current production (Equuleus):**

- [VyOS Operator Guide](../../../../docs/docs/network/vyos_operator_guide.md) - Current Equuleus deployment guide
- [VyOS Developer Guide](../../../../docs/docs/network/vyos_developer_guide.md) - Current Equuleus build pipeline

**External:**

- [VyOS 1.4 Documentation](https://docs.vyos.io/en/sagitta/)
- [OpenNebula Contextualization](https://docs.opennebula.io/6.8/management_and_operations/references/template.html#context-section)
- [VyOS Cloud-Init](https://docs.vyos.io/en/sagitta/automation/cloud-init.html)

---

*This document was updated with assistance from Claude Code (Opus 4.5).*
