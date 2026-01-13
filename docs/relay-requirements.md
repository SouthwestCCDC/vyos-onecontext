# VRF-Based Scoring Relay Contextualization Requirements

/// admonition
    type: note
This document defines requirements for the **vrouter-relay** role. It is separate from the
vrouter-infra design (see [design.md](design.md) and [context-reference.md](context-reference.md)).
///

## Problem Statement

Currently, reaching multiple isolated blue team networks from the scoring infrastructure requires
deploying a separate scoring relay VM for each target network. In 2025 regionals, with 5 target
networks per team and 10 teams, this would have required **50 relay VMs**.

By implementing VRF-based relays in 2025, we consolidated to **1 relay VM per team (10 total)**,
achieving an 80% reduction in infrastructure. However, this required post-deployment Ansible
configuration because our VyOS contextualization (vyos-onecontext) doesn't support VRF configuration.

**Goal**: Implement VRF relay capabilities in VyOS contextualization so relay routers are fully
configured on boot without requiring post-deployment Ansible configuration.

## Background: 2025 Regionals Implementation

### Architecture Overview

The 2025 approach used a single relay VM per team with:

- **1 ingress interface** (eth1) on shared relay ingress network (`game_relay_ingress`, 10.32.0.0/12)
- **5+ egress interfaces** (eth2-eth6) connected to different team networks
- **3 VRFs** to segregate traffic:
  - `relay` VRF: Ingress traffic routing
  - `office` VRF: Routes to office/internal networks
  - `cloud` VRF: Routes to cloud/datacenter networks

### Relay Ingress Network Architecture

The relay ingress network is a single large /12 (10.32.0.0 - 10.47.255.255). Within this space:

- **Relay "home" IP**: Each relay VM's eth1 has a base IP somewhere in the /12, typically placed
  to avoid conflicts with relay address blocks
- **Relay address blocks**: Various CIDR ranges within the /12 are used as relay addresses
  (e.g., 10.32.N.0/24, 10.33.N.0/24, 10.36.N.0/24, etc.)
- **Proxy ARP**: Relays respond to ARP for their assigned relay address blocks on the same
  interface as their home IP
- **All on one interface**: Both the home IP and all relay addresses are on eth1; policy routing
  and VRFs determine where traffic goes

This design means scoring infrastructure sends traffic to relay addresses (e.g., 10.32.5.100) on
the shared /12 network, and the relay VM responds via proxy-ARP, then routes through the
appropriate VRF to reach the actual target.

### Key Mechanisms

1. **Policy-Based Routing**: Traffic arriving at relay addresses on eth1 is routed to appropriate
   VRF based on destination address
2. **VRF-Aware NAT**: Destination NAT maps relay address ranges to target network ranges
   (subnet-based, not per-IP)
3. **Cross-VRF Routing**: VRFs can route through each other (e.g., office VRF default route via
   relay VRF)
4. **Proxy ARP**: Router responds to ARP for all relay addresses on ingress interface (same
   interface as home IP)

### What Was Configured

Example relay mapping for team 05:

- **Office networks via office VRF (eth2)**:
  - 10.32.5.X -> 192.168.144.X (office-clients)
  - 10.33.5.X -> 10.123.105.X (kanto-west)

- **Cloud networks via cloud VRF (eth3)**:
  - 10.36.5.X -> 10.101.105.X (office ISP)
  - 10.36.105.X -> 10.127.105.X (enterprise-cloud)
  - 10.37.5.X -> 10.123.105.X (kanto-west from cloud)
  - 10.37.105.X -> 10.124.105.X (kanto-east)
  - 10.37.205.X -> 10.125.105.X (johto-west)

Key point: Same target network (e.g., kanto-west at 10.123.105.X) is reachable via different
relay addresses depending on source VRF.

## Requirements

### Core Functional Requirements

#### FR1: VRF Definition and Management

- **Must** support defining multiple VRFs with unique names and routing table IDs
- **Must** support arbitrary number of VRFs (not hardcoded)
- **Must** bind network interfaces to specific VRFs
- **Should** validate VRF names and table IDs are unique

#### FR2: Policy-Based Routing

- **Must** support routing packets to specific VRF routing tables based on destination address
- **Must** support applying PBR policy to an ingress interface
- **Must** support multiple PBR rules per interface
- **Should** support CIDR prefix matching for destination addresses

#### FR3: VRF-Aware Routing

- **Must** support static routes within VRF context
- **Must** support default routes per VRF
- **Must** support cross-VRF next-hop routing (route in VRF A points to gateway in VRF B)
- **Must** support interface routes (for proxy-arp functionality)

#### FR4: VRF-Aware NAT

- **Must** support destination NAT operating in VRF context
- **Must** support subnet-based DNAT (entire CIDR -> entire CIDR) with arbitrary prefix lengths
- **Must** support source NAT (masquerade) on VRF-bound egress interfaces
- **Should** minimize NAT rule count (prefer subnet rules over per-IP rules)

#### FR5: Proxy ARP Support

- **Must** enable proxy-arp on ingress interface to respond for relay address ranges

#### FR6: Arbitrary Network Topology

- **Must** support arbitrary number of target networks per relay
- **Must** support arbitrary naming of VRFs and networks
- **Must** support different topologies per game without code changes
- **Must** support same target network reachable via multiple relay addresses (from different VRFs)

### Operational Requirements

#### OR1: Stateless Configuration

- **Must** configure entirely from OpenNebula context on every boot
- **Must not** require post-deployment configuration steps
- **Must not** require persistent configuration storage

#### OR2: Single Ingress Model

- **Must** support single ingress interface per relay router
- **Should** clearly identify ingress interface in configuration

#### OR3: Configuration Structure

- **Must** make it difficult to define invalid or inconsistent configurations through input structure
- **Should** provide clear validation errors if configuration is invalid
- **Should** support team-specific address calculation patterns

#### OR4: Maintainability

- **Should** share components with standard VyOS contextualization where practical
- **Should** document VRF-specific configuration patterns
- **May** use separate image/repository if beneficial for maintainability

### Non-Requirements

- **No backward compatibility** required with existing `SCORING_RELAY_NATS` parameter
- **No support for multiple ingress interfaces** per relay (single ingress only)
- **No support for non-VRF relays** in the new implementation (can be separate image)

## Design Considerations

### Design Direction: Virtual Relay Abstraction

Rather than requiring operators to manually define VRFs, routing tables, and PBR rules, the
configuration should be expressed as a set of **virtual scoring relays**. Each virtual relay
defines:

```text
(pivot_network, egress_interface, [
    (target_network_1, relay_address_range_1),
    (target_network_2, relay_address_range_2),
    ...
])
```

For example, a 2025 regionals-style configuration might be expressed as:

```text
# Virtual relay 1: "office" pivot
(office-clients, eth2, [
    (192.168.144.0/24, 10.32.N.0/24),      # office-clients
    (10.123.1NN.0/24, 10.33.N.0/24),       # kanto-west via office
])

# Virtual relay 2: "cloud" pivot
(enterprise-cloud, eth3, [
    (10.101.1NN.0/24, 10.36.N.0/24),       # office ISP
    (10.127.1NN.0/24, 10.36.1NN.0/24),     # enterprise-cloud
    (10.123.1NN.0/24, 10.37.N.0/24),       # kanto-west via cloud
    (10.124.1NN.0/24, 10.37.1NN.0/24),     # kanto-east
    (10.125.1NN.0/24, 10.37.2NN.0/24),     # johto-west
])
```

The contextualization implementation would then **derive**:

- VRF definitions (one per unique egress interface/pivot)
- VRF table IDs (auto-assigned)
- Interface-to-VRF bindings
- PBR rules (based on relay address ranges)
- DNAT rules (relay range -> target range)
- Source NAT rules (masquerade on egress interfaces)
- Static routes as needed

**Benefits of this approach**:

- Operators define *intent* ("reach X via Y") not *mechanism* (VRF table IDs, PBR rules)
- Impossible to create mismatched VRF/PBR/NAT configurations
- Same target reachable via multiple relay addresses naturally supported
- VRF grouping is automatic (same pivot = same VRF)

### Open Design Questions

These should be answered during implementation:

1. **Context Parameter Format**:
   - How to serialize the virtual relay definitions for OpenNebula context?
   - JSON? Custom DSL? Multiple parameters?

2. **Address Calculation**:
   - Should team number substitution (N, NN tokens) happen in contextualization script?
   - Or should Terraform calculate all addresses and pass them explicitly?

3. **Routing Details**:
   - How to specify default gateway per VRF?
   - How to handle cross-VRF routing requirements?

4. **Image Strategy**:
   - Separate relay-specific image vs extended standard router image?
   - If separate, what components can be shared?

### Implementation Guidance

**Flexibility Priority**: The solution must support arbitrary network topologies since every game
is different. Avoid hardcoding network names, VRF names, or topology assumptions.

**Example Scenarios to Support**:

- 2 VRFs with 3 target networks each (like 2025 regionals)
- 1 VRF with 8 target networks (like 2026 quals might need)
- Same target accessible from multiple relay address ranges
- Complex routing: VRF A -> VRF B -> VRF C -> external gateway

**Constraint Validation**: The input structure should make common mistakes impossible:

- Duplicate VRF table IDs
- Interface assigned to multiple VRFs
- Relay address overlaps
- Circular routing dependencies

## Success Criteria

1. **Functional**: A relay router deployed via Terraform with only context parameters successfully
   routes traffic from multiple relay address ranges to multiple target networks through
   appropriate VRFs

2. **Operational**: Relay router can be rebooted and automatically reconfigures correctly without
   manual intervention

3. **Flexible**: Same contextualization code supports different game topologies by changing only
   Terraform configuration, not contextualization code

4. **Maintainable**: Configuration is understandable and validatable, errors surface clearly

5. **Performance**: Configuration applies in reasonable time (<5 minutes for complex multi-VRF setup)

## References

- **2025 Implementation**: `deployment/ansible/roles/2025/regionals_infra/relay/`
- **VyOS Operator Guide**: See [VyOS Operator Guide](../../../../docs/docs/network/vyos_operator_guide.md)
- **2025 Relay Terraform**: `deployment/terraform/2025/regionals_infra/vrf_scoring_relays.tf`

## Related Documentation

- [Design Document](design.md) - vrouter-infra architecture (separate from relay)
- [Context Reference](context-reference.md) - vrouter-infra context variables
- [Requirements](../../../../docs/docs/projects/active/vyos-router-v3/requirements.md) - Project requirements

---

**Status**: Requirements defined, ready for design and implementation
