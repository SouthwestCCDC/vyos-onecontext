# VRF-Based Scoring Relay Design

## Overview

This document describes the design for VRF-based scoring relay support in VyOS Sagitta contextualization. This functionality enables the `vrouter-relay` image variant to route scoring traffic to multiple isolated team networks through VRFs, reducing infrastructure requirements by 80% compared to the previous approach of deploying separate relay VMs per target network.

**What relay routers do:**

- Accept traffic on a single ingress interface using proxy-ARP for multiple relay address ranges
- Route traffic to different target networks through VRF-isolated routing domains
- Perform subnet-to-subnet NAT to translate relay addresses to actual target addresses
- Support multiple target networks reachable via different relay address ranges

**Why VRF-based approach:**

VRFs (Virtual Routing and Forwarding) provide routing table isolation, enabling a single router to maintain separate routing domains for different network pivots. This allows one relay VM per team to handle multiple target networks that would previously have required separate relay VMs.

**Relationship to vrouter-infra:**

This design is specific to the `vrouter-relay` image variant and is **separate from the standard vrouter-infra design** (see [design.md](design.md)). While both share the vyos-onecontext codebase and many components, relay routers have distinct requirements and use a different context variable schema.

**References:**

- [Relay Requirements](relay-requirements.md) - Detailed requirements this design fulfills
- [Design Document](design.md) - Standard vrouter-infra architecture
- [Context Reference](context-reference.md) - Standard vrouter-infra context variables

## Use Case: 2026 Regionals

In 2025 regionals, we achieved an 80% reduction in relay infrastructure using VRF-based relays:

- **Previous approach**: 50 relay VMs (5 target networks × 10 teams)
- **VRF approach**: 10 relay VMs (1 per team)

For 2026 regionals, with fully-configured relay routers on boot, we aim to:

- Configure entirely from OpenNebula context (no post-deployment Ansible)
- Support arbitrary network topologies per game without code changes
- Maintain the same infrastructure efficiency

## JSON Schema

The relay configuration is expressed through a single `RELAY_JSON` context variable. This variable defines virtual relay mappings as a set of **pivots**, where each pivot represents a routing domain (egress interface + VRF) with one or more target networks.

### Complete Schema

```json
{
  "ingress_interface": "eth1",
  "pivots": [
    {
      "egress_interface": "eth2",
      "targets": [
        {
          "relay_prefix": "10.32.5.0/24",
          "target_prefix": "192.168.144.0/24",
          "gateway": "192.168.100.1"
        },
        {
          "relay_prefix": "10.33.5.0/24",
          "target_prefix": "10.123.105.0/24",
          "gateway": "192.168.100.1"
        }
      ]
    },
    {
      "egress_interface": "eth3",
      "targets": [
        {
          "relay_prefix": "10.36.5.0/24",
          "target_prefix": "10.101.105.0/24",
          "gateway": "10.101.105.1"
        },
        {
          "relay_prefix": "10.36.105.0/25",
          "target_prefix": "10.127.105.0/25",
          "gateway": "10.127.105.1"
        }
      ]
    }
  ]
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ingress_interface` | String | Yes | Interface receiving relay traffic (e.g., `eth1`) |
| `pivots` | Array | Yes | List of routing pivots (one VRF per pivot) |
| `pivots[].egress_interface` | String | Yes | Interface for this pivot's routing domain |
| `pivots[].targets` | Array | Yes | Target networks reachable via this pivot |
| `pivots[].targets[].relay_prefix` | CIDR | Yes | Relay address range (scoring sees these addresses) |
| `pivots[].targets[].target_prefix` | CIDR | Yes | Actual target network range (after NAT) |
| `pivots[].targets[].gateway` | IP | Yes | Next-hop gateway for target network (in VRF) |

### Validation Rules

The following validation rules are enforced by Pydantic models:

| Rule | Constraint |
|------|------------|
| Prefix length match | `relay_prefix` and `target_prefix` must have identical prefix lengths |
| Unique relay prefixes | No two `relay_prefix` values may overlap |
| Unique egress interfaces | Each `egress_interface` must appear in only one pivot |
| Ingress != egress | `ingress_interface` must not match any `egress_interface` |
| Valid interface format | Interface names must match pattern `eth[0-9]+` |
| Valid IP addresses | `gateway` must be valid IPv4 address |
| Valid CIDR prefixes | All prefix fields must be valid IPv4 CIDR notation |

### Design Rationale

**Why pivot-based structure?**

The pivot abstraction groups targets by their routing domain (egress interface). This makes VRF derivation automatic: one VRF per unique egress interface. Operators define *intent* ("reach these targets via this interface") rather than *mechanism* (VRF table IDs, PBR rule numbers).

**Why enforce matching prefix lengths?**

VyOS subnet-to-subnet NAT (netmap) requires identical prefix lengths. This constraint is fundamental to the NAT mechanism and prevents configuration errors.

**Why per-target gateways?**

Different target networks may have different next-hop gateways, even when reachable through the same egress interface. Per-target gateways provide maximum flexibility.

**Why implicit VRF derivation?**

Automatic VRF creation from pivots ensures consistency and eliminates the possibility of mismatched VRF/interface/NAT configurations. Table IDs are auto-assigned, avoiding conflicts.

## Derived Configuration

From the JSON schema, the relay generator derives all VyOS configuration automatically. The following sections describe what is generated and how.

### VRFs and Interface Binding

**One VRF per unique egress interface:**

```
set vrf name relay_eth2 table 150
set vrf name relay_eth3 table 151
set interfaces ethernet eth2 vrf relay_eth2
set interfaces ethernet eth3 vrf relay_eth3
```

**VRF naming:** `relay_{interface_name}` (e.g., `relay_eth2`, `relay_eth3`)

**Table ID assignment:** Sequential allocation starting at 150 (avoiding table 100 reserved for management VRF, respecting VyOS max of 200)

### Policy-Based Routing (PBR)

**Route relay traffic to appropriate VRF based on destination:**

```
set policy route relay-pbr rule 10 set table 150
set policy route relay-pbr rule 10 destination address 10.32.5.0/24
set policy route relay-pbr rule 20 set table 150
set policy route relay-pbr rule 20 destination address 10.33.5.0/24
set policy route relay-pbr rule 30 set table 151
set policy route relay-pbr rule 30 destination address 10.36.5.0/24
set policy route relay-pbr rule 40 set table 151
set policy route relay-pbr rule 40 destination address 10.36.105.0/25
set interfaces ethernet eth1 policy route relay-pbr
```

**Rule numbering:** Sequential (10, 20, 30, ...) for each relay_prefix

**Policy name:** Fixed as `relay-pbr`

**Application:** Applied to the ingress interface

### Destination NAT (Subnet-to-Subnet)

**Translate relay addresses to target addresses:**

```
set nat destination rule 5000 inbound-interface name eth1
set nat destination rule 5000 destination address 10.32.5.0/24
set nat destination rule 5000 translation address 192.168.144.0/24
set nat destination rule 5010 inbound-interface name eth1
set nat destination rule 5010 destination address 10.33.5.0/24
set nat destination rule 5010 translation address 10.123.105.0/24
set nat destination rule 5020 inbound-interface name eth1
set nat destination rule 5020 destination address 10.36.5.0/24
set nat destination rule 5020 translation address 10.101.105.0/24
set nat destination rule 5030 inbound-interface name eth1
set nat destination rule 5030 destination address 10.36.105.0/25
set nat destination rule 5030 translation address 10.127.105.0/25
```

**Rule numbering:** Starts at 5000, increments by 10 (avoiding conflict with standard NAT_JSON rules which use idx*100 scheme)

**NAT type:** Subnet-to-subnet (netmap) - one rule per target regardless of prefix size

**Note:** VyOS Sagitta netmap syntax needs verification on real instance (syntax may differ from Equuleus)

### Source NAT (Masquerade)

**Masquerade outbound traffic on each egress interface:**

```
set nat source rule 5000 outbound-interface name eth2
set nat source rule 5000 translation address masquerade
set nat source rule 5010 outbound-interface name eth3
set nat source rule 5010 translation address masquerade
```

**Rule numbering:** Starts at 5000, increments by 10 (parallel with DNAT numbering)

**One rule per pivot:** All targets using the same egress interface share one masquerade rule

### Proxy-ARP

**Enable proxy-ARP on ingress interface to respond for relay address ranges:**

```
set interfaces ethernet eth1 ip enable-proxy-arp
```

**Expected behavior:** Router responds to ARP requests for any address in relay_prefix ranges, even though those addresses aren't directly configured on the interface. (Needs validation on Sagitta - see Open Questions section.)

**Why needed:** Relay addresses and the ingress interface's home IP are all on the same large /12 network. Proxy-ARP allows the router to claim ownership of relay addresses without explicit secondary IPs.

### Static Routes (Per-VRF)

**Route target networks via specified gateways in VRF context:**

```
set vrf name relay_eth2 protocols static route 192.168.144.0/24 next-hop 192.168.100.1
set vrf name relay_eth2 protocols static route 10.123.105.0/24 next-hop 192.168.100.1
set vrf name relay_eth3 protocols static route 10.101.105.0/24 next-hop 10.101.105.1
set vrf name relay_eth3 protocols static route 10.127.105.0/25 next-hop 10.127.105.1
```

**Scope:** All routes are in VRF routing tables, not the global routing table

**Per-target routes:** Each target gets its own static route in the appropriate VRF

## Pydantic Models

The relay configuration is validated using Pydantic models with automatic schema enforcement.

### Model Structure

```python
from pydantic import BaseModel, field_validator, model_validator
from ipaddress import IPv4Address, IPv4Network

class RelayTarget(BaseModel):
    """A single relay target (relay prefix -> target network)."""
    relay_prefix: str
    target_prefix: str
    gateway: IPv4Address

    @field_validator('relay_prefix', 'target_prefix')
    @classmethod
    def validate_prefix(cls, v: str) -> str:
        """Validate IPv4 CIDR notation."""
        IPv4Network(v, strict=False)
        return v

    @model_validator(mode='after')
    def validate_prefix_lengths_match(self) -> 'RelayTarget':
        """Ensure relay_prefix and target_prefix have matching lengths."""
        relay_net = IPv4Network(self.relay_prefix, strict=False)
        target_net = IPv4Network(self.target_prefix, strict=False)
        if relay_net.prefixlen != target_net.prefixlen:
            raise ValueError(
                f"relay_prefix ({self.relay_prefix}) and target_prefix "
                f"({self.target_prefix}) must have matching prefix lengths"
            )
        return self


class PivotConfig(BaseModel):
    """A routing pivot (egress interface + targets)."""
    egress_interface: str
    targets: list[RelayTarget]

    @field_validator('egress_interface')
    @classmethod
    def validate_interface_format(cls, v: str) -> str:
        """Validate interface name format."""
        if not v.startswith('eth') or not v[3:].isdigit():
            raise ValueError(f"Invalid interface format: {v} (must be ethN)")
        return v

    @model_validator(mode='after')
    def validate_has_targets(self) -> 'PivotConfig':
        """Ensure at least one target per pivot."""
        if not self.targets:
            raise ValueError("Each pivot must have at least one target")
        return self


class RelayConfig(BaseModel):
    """Complete relay router configuration."""
    ingress_interface: str
    pivots: list[PivotConfig]

    @field_validator('ingress_interface')
    @classmethod
    def validate_interface_format(cls, v: str) -> str:
        """Validate interface name format."""
        if not v.startswith('eth') or not v[3:].isdigit():
            raise ValueError(f"Invalid interface format: {v} (must be ethN)")
        return v

    @model_validator(mode='after')
    def validate_relay_config(self) -> 'RelayConfig':
        """Cross-reference validation."""
        # Check unique egress interfaces
        egress_ifaces = [p.egress_interface for p in self.pivots]
        if len(egress_ifaces) != len(set(egress_ifaces)):
            duplicates = sorted(
                {iface for iface in egress_ifaces if egress_ifaces.count(iface) > 1}
            )
            raise ValueError(f"Duplicate egress interfaces: {duplicates}")

        # Check ingress != egress
        if self.ingress_interface in egress_ifaces:
            raise ValueError(
                f"ingress_interface ({self.ingress_interface}) cannot be "
                "used as an egress_interface"
            )

        # Check no overlapping relay prefixes
        relay_prefixes = [
            target.relay_prefix
            for pivot in self.pivots
            for target in pivot.targets
        ]
        # Convert to IPv4Network for overlap detection
        relay_networks = [IPv4Network(p, strict=False) for p in relay_prefixes]
        for i, net1 in enumerate(relay_networks):
            for net2 in relay_networks[i+1:]:
                if net1.overlaps(net2):
                    raise ValueError(
                        f"Overlapping relay prefixes: {net1} and {net2}"
                    )

        # Ensure at least one pivot
        if not self.pivots:
            raise ValueError("At least one pivot is required")

        return self
```

### Validation Error Examples

**Prefix length mismatch:**
```
ERROR: Validation failed for RELAY_JSON:
  pivots[0].targets[0]: relay_prefix (10.32.5.0/24) and target_prefix
  (192.168.144.0/25) must have matching prefix lengths
```

**Overlapping relay prefixes:**
```
ERROR: Validation failed for RELAY_JSON:
  Overlapping relay prefixes: 10.32.5.0/24 and 10.32.5.0/25
```

**Duplicate egress interface:**
```
ERROR: Validation failed for RELAY_JSON:
  Duplicate egress interfaces: ['eth2']
```

**Ingress used as egress:**
```
ERROR: Validation failed for RELAY_JSON:
  ingress_interface (eth1) cannot be used as an egress_interface
```

## Generator Architecture

The relay generator is a **new, standalone generator** that produces its own VRF, PBR, NAT, and routing commands. It does NOT reuse the existing NAT or VRF generators from standard vrouter-infra configuration.

### Why Separate Generator?

Relay NAT is structurally different from standard NAT:

| Aspect | Standard NAT (NAT_JSON) | Relay NAT (RELAY_JSON) |
|--------|-------------------------|------------------------|
| Scope | Global routing table | VRF-aware |
| NAT type | Per-rule: masquerade, port forwarding, 1:1 | Subnet-to-subnet (netmap) |
| Configuration | Explicit rules in JSON | Derived from pivot/target mappings |
| Rule numbering | 100+ range | 5000+ range (avoids conflicts) |

Attempting to reuse the standard NAT generator would require extensive conditional logic and risk breaking existing NAT functionality. A separate generator provides clean separation of concerns.

### Generator Composition

```python
# Proposed change to vyos_onecontext/generators/__init__.py
def generate_config(config: RouterConfig) -> list[str]:
    """Generate all VyOS commands from parsed config."""
    commands = []

    # System configuration
    commands.extend(HostnameGenerator(config.hostname).generate())
    commands.extend(SshKeyGenerator(config.ssh_public_key).generate())

    # VRF configuration (management VRF)
    commands.extend(VrfGenerator(config.interfaces).generate())

    # Interface configuration
    commands.extend(InterfaceGenerator(config.interfaces, config.aliases).generate())

    # Relay generator (new - only runs if RELAY_JSON present)
    if config.relay:
        commands.extend(RelayGenerator(config.relay).generate())

    # ... (standard generators: routing, SSH service, OSPF, DHCP, NAT, firewall, conntrack, custom config)

    return commands
```

### RelayGenerator Implementation

```python
class RelayGenerator(BaseGenerator):
    """Generate VyOS commands for VRF-based relay configuration."""

    BASE_TABLE_ID = 150  # Start VRF table IDs at 150
    DNAT_RULE_START = 5000  # Avoid conflict with standard NAT (idx*100 scheme)
    SNAT_RULE_START = 5000
    PBR_RULE_INCREMENT = 10

    def __init__(self, relay: RelayConfig) -> None:
        self.relay = relay

    def generate(self) -> list[str]:
        """Generate all relay commands."""
        commands = []

        commands.extend(self._generate_vrfs())
        commands.extend(self._generate_pbr())
        commands.extend(self._generate_dnat())
        commands.extend(self._generate_snat())
        commands.extend(self._generate_proxy_arp())
        commands.extend(self._generate_static_routes())

        return commands

    def _generate_vrfs(self) -> list[str]:
        """Create VRFs and bind interfaces."""
        commands = []
        for idx, pivot in enumerate(self.relay.pivots):
            vrf_name = f"relay_{pivot.egress_interface}"
            table_id = self.BASE_TABLE_ID + idx

            commands.append(f"set vrf name {vrf_name} table {table_id}")
            commands.append(
                f"set interfaces ethernet {pivot.egress_interface} "
                f"vrf {vrf_name}"
            )

        return commands

    def _generate_pbr(self) -> list[str]:
        """Generate policy-based routing rules."""
        commands = []
        rule_num = 10

        # Build VRF table ID mapping
        vrf_table_map = {
            pivot.egress_interface: self.BASE_TABLE_ID + idx
            for idx, pivot in enumerate(self.relay.pivots)
        }

        # Create PBR rules for each target
        for pivot in self.relay.pivots:
            table_id = vrf_table_map[pivot.egress_interface]
            for target in pivot.targets:
                commands.append(
                    f"set policy route relay-pbr rule {rule_num} "
                    f"set table {table_id}"
                )
                commands.append(
                    f"set policy route relay-pbr rule {rule_num} "
                    f"destination address {target.relay_prefix}"
                )
                rule_num += self.PBR_RULE_INCREMENT

        # Apply policy to ingress interface
        commands.append(
            f"set interfaces ethernet {self.relay.ingress_interface} "
            f"policy route relay-pbr"
        )

        return commands

    def _generate_dnat(self) -> list[str]:
        """Generate destination NAT (subnet-to-subnet)."""
        commands = []
        rule_num = self.DNAT_RULE_START

        for pivot in self.relay.pivots:
            for target in pivot.targets:
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"inbound-interface name {self.relay.ingress_interface}"
                )
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"destination address {target.relay_prefix}"
                )
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"translation address {target.target_prefix}"
                )
                rule_num += 10

        return commands

    def _generate_snat(self) -> list[str]:
        """Generate source NAT (masquerade per egress)."""
        commands = []
        rule_num = self.SNAT_RULE_START

        for pivot in self.relay.pivots:
            commands.append(
                f"set nat source rule {rule_num} "
                f"outbound-interface name {pivot.egress_interface}"
            )
            commands.append(
                f"set nat source rule {rule_num} "
                f"translation address masquerade"
            )
            rule_num += 10

        return commands

    def _generate_proxy_arp(self) -> list[str]:
        """Enable proxy-ARP on ingress interface."""
        return [
            f"set interfaces ethernet {self.relay.ingress_interface} "
            f"ip enable-proxy-arp"
        ]

    def _generate_static_routes(self) -> list[str]:
        """Generate static routes in VRF context."""
        commands = []

        for pivot in self.relay.pivots:
            vrf_name = f"relay_{pivot.egress_interface}"
            for target in pivot.targets:
                commands.append(
                    f"set vrf name {vrf_name} protocols static route "
                    f"{target.target_prefix} next-hop {target.gateway}"
                )

        return commands
```

## Boot Flow Integration

The relay generator integrates into the existing boot flow after interface configuration but before standard routing/NAT.

### Execution Order

```
1. System configuration (hostname, SSH keys)
2. VRF configuration (management VRF - must come before interface IP configuration)
3. Relay VRFs and interface bindings (if RELAY_JSON present - must come before interface IP configuration)
4. Interface configuration (IP addresses, MTU)
5. Relay configuration continued (if RELAY_JSON present)
   ├─ Policy-based routing
   ├─ Relay NAT (DNAT + SNAT)
   ├─ Proxy-ARP
   └─ Static routes in VRF context
6. Routing (default gateway selection for non-management interfaces)
7. Static routes (ROUTES_JSON)
8. SSH service (VRF binding)
9. OSPF (OSPF_JSON)
10. DHCP (DHCP_JSON)
11. NAT (NAT_JSON - rules 100+)
12. Firewall (FIREWALL_JSON)
13. Conntrack timeouts
14. Custom commands (START_CONFIG)
15. Commit configuration
16. Custom scripts (START_SCRIPT)
```

### Why This Order?

In this project, configuration is generated and applied by Python: the relay generators build an ordered list of `set` commands, which are then executed via `VyOSConfigSession.run_commands`. The command ordering matters because VyOS does **not** resolve ordering dependencies automatically during commit. Referencing undefined objects (e.g., assigning an interface to a non-existent VRF, or referencing a firewall group that hasn't been created yet) causes commit failure.

The ordering above reflects **correctness requirements**, not just logical grouping:

1. **System and network fundamentals first**: Hostname and VRFs establish the base configuration before interfaces reference them
2. **VRFs before interface IPs**: VRFs (both management and relay) must be created before interfaces are assigned to them
3. **Relay VRFs split across steps**: VRF creation and interface binding happen before interface IP configuration (step 3), while PBR/NAT/routing happen after (step 5)
4. **Standard features after relay**: Standard routing, NAT, OSPF, etc. operate in the global routing table and don't interact with relay VRF config
5. **Escape hatches last**: START_CONFIG and START_SCRIPT run after all structured configuration, allowing manual overrides

**Note:** The existing codebase orders management VRF creation before interface IP
configuration because **VRFs must be defined before interfaces can reference them**.
This is a correctness requirement in VyOS Sagitta, not just a convention. The relay
generator follows the same ordering for the same reason.

> **Implementation Note — VyOS ordering constraints:**
>
> VyOS does not resolve ordering dependencies automatically during commit. Referencing undefined objects (e.g., assigning an interface to a non-existent VRF, or referencing a firewall group that hasn't been created yet) causes commit failure. This ordering is a correctness requirement.
>
> References:
> - VRF docs: https://docs.vyos.io/en/1.4/configuration/vrf/index.html
> - Phabricator T6423 (mandatory priorities): https://vyos.dev/T6423
> - Phabricator T6559 (dependency errors): https://vyos.dev/T6559
> - Forum discussion: https://forum.vyos.io/t/order-of-command-in-a-command-set/15576

### RouterConfig Changes

The `RouterConfig` model gains an optional `relay` field:

```python
class RouterConfig(BaseModel):
    """Complete router configuration."""
    hostname: str | None = None
    ssh_public_key: str | None = None
    onecontext_mode: OnecontextMode = OnecontextMode.STATELESS
    interfaces: list[InterfaceConfig] = Field(default_factory=list)
    aliases: list[AliasConfig] = Field(default_factory=list)
    routes: RoutesConfig | None = None
    ospf: OspfConfig | None = None
    dhcp: DhcpConfig | None = None
    nat: NatConfig | None = None
    firewall: FirewallConfig | None = None
    conntrack: ConntrackConfig | None = None
    relay: RelayConfig | None = None  # NEW
    start_config: str | None = None
    start_script: str | None = None
    start_script_timeout: int = 300
```

## Interaction with Standard Config

Relay configuration can coexist with standard vrouter-infra configuration on the same router, though this is not expected in typical deployments.

### Rule Number Ranges

**NAT rules:**

| Range | Purpose |
|-------|---------|
| 1-99 | Reserved for manual rules via START_CONFIG |
| 100+ | Standard NAT_JSON source/destination rules (`idx * 100`, no upper bound) |
| 500+ | Standard NAT_JSON binat rules (`500 + idx * 100`, shares namespace with above) |
| 5000+ | Relay NAT rules (subnet-to-subnet DNAT/SNAT) |

Standard source/destination NAT uses `idx * 100` numbering with no cap. Binat rules start at `500 + idx * 100`. In practice, relay routers are dedicated appliances unlikely to also have extensive standard NAT rules. With 5000 as the relay base, a collision would require 50+ standard source/destination NAT rules or 46+ binat rules on the same router — unrealistic for a dedicated relay appliance.

**VRF table IDs:**

| Range | Purpose |
|-------|---------|
| 100 | Management VRF (if VROUTER_MANAGEMENT=YES) |
| 150-200 | Relay VRFs (auto-assigned, max 50 pivots) |

**Firewall rules:**

Relay routers typically don't use FIREWALL_JSON. If needed, firewall rules are per-policy (zone-to-zone) and don't conflict with relay configuration.

### Compatibility Notes

- **RELAY_JSON + NAT_JSON**: Both can be present. Relay NAT rules (5000+) are unlikely to collide with standard NAT rules (source/destination at `idx * 100`, binat at `500 + idx * 100`) on a dedicated relay appliance. A collision would require 50+ standard rules or 46+ binat rules.
- **RELAY_JSON + VROUTER_MANAGEMENT**: Both can be present. Management VRF uses table 100; relay VRFs use 150-200.
- **RELAY_JSON + ROUTES_JSON**: Standard routes go in global routing table; relay routes go in VRF tables. No conflict.
- **RELAY_JSON + OSPF_JSON**: OSPF would run in global routing table, not in relay VRFs. Unlikely combination, but technically compatible.

## Image Strategy

### Separate Packer Template, Same Codebase

**Decision:** Use the same vyos-onecontext codebase but create a separate Packer template for relay images.

**Rationale:**

| Aspect | Same Codebase | Separate Template |
|--------|---------------|-------------------|
| Code reuse | Shared models, parsers, base generators | Different provisioning steps |
| Testing | Shared test suite + relay-specific tests | Different integration test scenarios |
| Versioning | Single version, single release cycle | Distinct image artifacts |
| Maintenance | One codebase to update | Two image build pipelines |

**Why not a single image variant?**

Relay and infra routers have different operational profiles:

- **vrouter-infra**: General-purpose routing, NAT gateway, OSPF, DHCP server
- **vrouter-relay**: Specialized VRF relay, no DHCP/OSPF expected, distinct network topology

Separate images provide:
- Clearer operational semantics (relay vs. general routing)
- Easier troubleshooting (distinct image = distinct purpose)
- Potential for different base configurations or optimizations

**Build process:**

1. CI builds vyos-onecontext wheel (once)
2. Packer builds vrouter-infra image using wheel
3. Packer builds vrouter-relay image using same wheel
4. Both images share Python code, differ in image naming/tagging

### Packer Template Structure

```hcl
# packer/opennebula-context/vyos-relay/vyos-relay.pkr.hcl

source "qemu" "vyos-relay" {
  # Base VyOS ISO (same as vrouter-infra)
  iso_url = var.vyos_iso_url
  # ... QEMU config ...
}

build {
  sources = ["source.qemu.vyos-relay"]

  # Install vyos-onecontext wheel (same as vrouter-infra)
  provisioner "file" {
    source      = "${var.wheel_path}"
    destination = "/tmp/vyos_onecontext.whl"
  }

  provisioner "shell" {
    inline = [
      "python3 -m venv /opt/vyos-onecontext/venv",
      "/opt/vyos-onecontext/venv/bin/pip install /tmp/vyos_onecontext.whl",
      "rm /tmp/vyos_onecontext.whl"
    ]
  }

  # Install boot hook (same script as vrouter-infra)
  provisioner "file" {
    source      = "../../files/vyos-postconfig-bootup.script"
    destination = "/tmp/vyos-postconfig-bootup.script"
  }

  provisioner "shell" {
    inline = [
      "mv /tmp/vyos-postconfig-bootup.script /config/scripts/",
      "chmod 755 /config/scripts/vyos-postconfig-bootup.script"
    ]
  }

  # Relay-specific tagging (if desired)
  post-processor "manifest" {
    output = "manifest-relay.json"
  }
}
```

**Key point:** Both images use the exact same Python code. The `RelayGenerator` only activates when `RELAY_JSON` is present, so vrouter-infra images can ignore it and relay images can use it.

## Open Questions / Needs Verification

The following aspects need verification on a real VyOS Sagitta instance before implementation:

### 1. Subnet-to-Subnet NAT (netmap) Syntax

**Question:** Does VyOS Sagitta support netmap syntax as shown below?

```
set nat destination rule 5000 destination address 10.32.5.0/24
set nat destination rule 5000 translation address 192.168.144.0/24
```

**Expected behavior:** Traffic destined for 10.32.5.X is translated to 192.168.144.X (subnet-wide mapping).

**Verification needed:**
- Confirm this syntax is valid in Sagitta
- Confirm it produces the expected nftables rules
- Test with different prefix lengths (/24, /25, /26)
- Verify behavior with non-matching prefix lengths (should fail or warn)

**Fallback if unsupported:**
If netmap isn't supported, we would need to generate per-IP DNAT rules, which is impractical for large prefixes. This would be a blocking issue requiring either:
- VyOS version upgrade (if newer version supports it)
- Custom nftables rules via START_CONFIG
- Redesign to use different NAT approach

### 2. Policy-Based Routing Syntax

**Question:** Is the PBR syntax correct for routing to VRF tables?

```
set policy route relay-pbr rule 10 set table 150
set policy route relay-pbr rule 10 destination address 10.32.5.0/24
set interfaces ethernet eth1 policy route relay-pbr
```

**Expected behavior:** Traffic matching destination address is routed to table 150 (VRF routing table).

**Verification needed:**
- Confirm `set table` syntax is correct (not `set vrf` or other variant)
- Test that traffic actually routes through the correct VRF
- Verify interaction with global routing table (fallback behavior)

### 3. VRF Static Route Syntax

**Question:** Is the VRF static route syntax correct?

```
set vrf name relay_eth2 protocols static route 192.168.144.0/24 next-hop 192.168.100.1
```

**Expected behavior:** Route exists in VRF `relay_eth2` routing table, not global table.

**Verification needed:**
- Confirm syntax is correct for VRF-scoped routes
- Test that routes appear in correct VRF table (`ip route show vrf relay_eth2`)
- Verify routes don't leak into global routing table

### 4. Proxy-ARP Behavior

**Question:** Does proxy-ARP work as expected for non-local addresses?

```
set interfaces ethernet eth1 ip enable-proxy-arp
```

**Expected behavior:** Router responds to ARP for relay addresses (10.32.5.0/24, etc.) even though they're not configured as interface IPs.

**Verification needed:**
- Confirm router responds to ARP for relay address ranges
- Verify this works with policy routing (ARP response doesn't imply routing)
- Test behavior with multiple relay prefixes on same interface

## Implementation Phases

Suggested phased approach for implementation:

### Phase 1: Pydantic Models + Validation + Unit Tests

**Deliverables:**
- `RelayTarget`, `PivotConfig`, `RelayConfig` models
- All field validators
- Cross-reference validation
- Comprehensive unit tests for validation rules

**Acceptance criteria:**
- All validation rules pass tests
- Clear error messages for all validation failures
- 100% test coverage on validation logic

### Phase 2: Relay Generator (VRF, PBR, NAT, Routing, Proxy-ARP Commands)

**Deliverables:**
- `RelayGenerator` class with all generation methods
- Unit tests for command generation
- Test fixtures covering various relay configurations

**Acceptance criteria:**
- Generator produces correct VyOS commands for sample configs
- Commands match expected syntax (modulo verification results)
- Tests cover edge cases (single target, many targets, multiple pivots)

### Phase 3: Parser Integration (RELAY_JSON Variable)

**Deliverables:**
- Context parser recognizes RELAY_JSON
- JSON parsing into RelayConfig model
- Error handling for malformed JSON

**Acceptance criteria:**
- Parser handles valid RELAY_JSON
- Parser rejects invalid JSON with clear errors
- Integration tests with sample context files

### Phase 4: Boot Flow Integration + RouterConfig Changes

**Deliverables:**
- Add `relay` field to RouterConfig
- Integrate RelayGenerator into generator sequence
- Update main entry point to handle RELAY_JSON

**Acceptance criteria:**
- Relay config generates in correct order
- Standard config still works without RELAY_JSON
- No conflicts with existing generators

### Phase 5: Integration Testing on Real VyOS Sagitta

**Deliverables:**
- Build relay image with contextualization
- Test relay config on real VyOS instance
- Verify netmap, PBR, VRF routing, proxy-ARP

**Acceptance criteria:**
- Router boots and applies relay config
- Traffic flows through correct VRFs
- NAT translations work correctly
- No syntax errors or commit failures

### Phase 6: Packer Template + Terraform Module

**Deliverables:**
- Packer template for vrouter-relay image
- Terraform module for deploying relay routers
- Documentation for relay deployment

**Acceptance criteria:**
- Packer builds relay image successfully
- Terraform deploys relay router with RELAY_JSON
- End-to-end scoring traffic flows through relay

## Related Documentation

- [Relay Requirements](relay-requirements.md) - Requirements this design fulfills
- [Design Document](design.md) - Standard vrouter-infra architecture
- [Context Reference](context-reference.md) - Standard vrouter-infra context variables
- [VyOS 1.4 Documentation](https://docs.vyos.io/en/sagitta/) - Official VyOS Sagitta docs

---

*This document was developed with assistance from Claude Code (Opus 4.6).*
