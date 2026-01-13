# Context Variable Reference

This document defines all context variables supported by VyOS Sagitta contextualization.

## Standard OpenNebula Variables

These variables follow OpenNebula conventions and provide basic network configuration.

### Network Interface Variables

For each interface (eth0, eth1, ...), the following variables are supported:

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `ETHx_IP` | IP address | No | IPv4 address for interface |
| `ETHx_MASK` | Netmask | No | Dotted-decimal netmask (e.g., `255.255.255.0`) |
| `ETHx_GATEWAY` | IP address | No | Default gateway via this interface |
| `ETHx_DNS` | IP address | No | DNS server |
| `ETHx_MTU` | Integer | No | Interface MTU |
| `ETHx_VROUTER_MANAGEMENT` | `YES`/`NO` | No | Place interface in management VRF |

**Example:**

```bash
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_GATEWAY="10.0.1.254"
ETH0_DNS="8.8.8.8"
ETH0_MTU="1500"
ETH0_VROUTER_MANAGEMENT="YES"
```

**Notes:**

- If `ETHx_GATEWAY` is set and the interface is not management, a default route is added
- Multiple interfaces can have `VROUTER_MANAGEMENT="YES"` (all go in management VRF)
- Netmask is converted to CIDR prefix automatically

### NIC Alias Variables (Secondary IPs)

OpenNebula NIC aliases provide additional IP addresses on the same interface. These are
used for 1:1 NAT scenarios where additional public IPs are needed.

For each alias on an interface, the following variables are provided:

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `ETHx_ALIASy_IP` | IP address | No | IPv4 address for alias |
| `ETHx_ALIASy_MASK` | Netmask | No | Dotted-decimal netmask (may be empty due to ONE bug) |
| `ETHx_ALIASy_MAC` | MAC address | No | MAC address (same as parent interface) |

**Example:**

```bash
# Primary interface
ETH0_IP="129.244.246.64"
ETH0_MASK="255.255.255.0"

# First alias (for scoring engine 1:1 NAT)
ETH0_ALIAS0_IP="129.244.246.66"
ETH0_ALIAS0_MASK="255.255.255.0"

# Second alias (for another service)
ETH0_ALIAS1_IP="129.244.246.67"
ETH0_ALIAS1_MASK="255.255.255.0"
```

**Notes:**

- Aliases are configured in Terraform using `nic_alias` blocks
- OpenNebula manages IP allocation from the virtual network
- The contextualization script adds these as secondary addresses on the interface
- If `ETHx_ALIASy_MASK` is empty (known ONE bug), the parent interface mask is used
- Alias IPs can be referenced in `NAT_JSON` binat rules for 1:1 NAT

### Identity Variables

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `HOSTNAME` | String | No | System hostname |
| `SSH_PUBLIC_KEY` | String | No | SSH public key for vyos user |

**Example:**

```bash
HOSTNAME="router-01"
SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host"
```

### Operational Variables

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `ONECONTEXT_MODE` | String | No | Save behavior: `stateless` (default), `save`, `freeze` |

**Values:**

| Value | Behavior | Consistency | Recommended |
|-------|----------|-------------|-------------|
| `stateless` | Don't save. Regenerate fresh every boot. | Guaranteed | Yes (default) |
| `save` | Save after commit. Still run onecontext on future boots. | **None** | No - escape hatch only |
| `freeze` | Save and disable onecontext hook. Future boots use saved config. | N/A | For handoff to manual management |

**Example:**

```bash
# Normal operation (default - can be omitted)
ONECONTEXT_MODE="stateless"

# Freeze router for manual management
ONECONTEXT_MODE="freeze"
```

**Notes:**

- Default is `stateless` if not specified
- `save` mode has no consistency guarantees: next boot starts from saved state rather than
  fresh, so context changes may conflict with leftover config. Use only if you have a specific need.
- `freeze` mode disables the onecontext boot hook entirely. Once frozen, the operator owns
  the configuration and the contextualization system is not involved in future boots.
- All modes emit a descriptive message at the end of contextualization indicating what was done

---

## JSON Extension Variables

These variables use JSON encoding for complex configuration. In Terraform, use `jsonencode()`:

```hcl
context = {
  ROUTES_JSON = jsonencode({
    static = [
      { interface = "eth1", destination = "0.0.0.0/0", gateway = "10.63.255.1" }
    ]
  })
}
```

### ROUTES_JSON

Static routing configuration.

**Schema:**

```json
{
  "static": [
    {
      "interface": "eth1",
      "destination": "0.0.0.0/0",
      "gateway": "10.63.255.1",
      "distance": 1,
      "vrf": "management"
    }
  ]
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `static` | Array | Yes | List of static routes |
| `static[].interface` | String | Yes | Egress interface |
| `static[].destination` | CIDR | Yes | Destination network |
| `static[].gateway` | IP | No | Next-hop gateway (if not specified, uses interface route) |
| `static[].distance` | Integer | No | Administrative distance (default: 1) |
| `static[].vrf` | String | No | VRF name (default: main routing table) |

**Terraform Example:**

```hcl
ROUTES_JSON = jsonencode({
  static = [
    { interface = "eth1", destination = "0.0.0.0/0", gateway = "10.63.255.1" },
    { interface = "eth2", destination = "10.96.0.0/13", gateway = "10.69.100.1" },
    { interface = "eth0", destination = "192.168.0.0/16", gateway = "10.0.1.254", vrf = "management" }
  ]
})
```

**Generated VyOS Commands:**

```
set protocols static route 0.0.0.0/0 next-hop 10.63.255.1
set protocols static route 10.96.0.0/13 next-hop 10.69.100.1
set vrf name management protocols static route 192.168.0.0/16 next-hop 10.0.1.254
```

---

### OSPF_JSON

OSPF dynamic routing configuration using interface-based syntax (Sagitta best practice).

**Schema:**

```json
{
  "enabled": true,
  "router_id": "10.0.0.1",
  "interfaces": [
    {
      "name": "eth1",
      "area": "0.0.0.0",
      "passive": false,
      "cost": 10
    },
    {
      "name": "eth2",
      "area": "0.0.0.0",
      "passive": true
    }
  ],
  "redistribute": ["connected", "static"],
  "default_information": {
    "originate": true,
    "always": true,
    "metric": 100
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | Boolean | Yes | Enable OSPF |
| `router_id` | IP | No | OSPF router ID (auto-derived if not set) |
| `interfaces` | Array | Yes | OSPF interface configurations |
| `interfaces[].name` | String | Yes | Interface name (e.g., `eth1`) |
| `interfaces[].area` | String | Yes | Area ID (dotted-decimal, e.g., `0.0.0.0`) |
| `interfaces[].passive` | Boolean | No | If true, advertise network but don't form adjacencies (default: false) |
| `interfaces[].cost` | Integer | No | Interface cost metric (default: auto-calculated) |
| `redistribute` | Array | No | Protocols to redistribute: `connected`, `static`, `kernel` |
| `default_information` | Object | No | Default route origination settings |
| `default_information.originate` | Boolean | No | Originate default route into OSPF |
| `default_information.always` | Boolean | No | Always originate even without default route in RIB |
| `default_information.metric` | Integer | No | Metric for originated default route |

> **Note:** OSPF authentication is not included in v1. The OSPF networks run on isolated
> point-to-point links with adequate protection at the infrastructure level. Authentication
> support may be added in a future version if needed.

**Passive interfaces explained:**

A passive interface advertises its connected network into OSPF but does **not** form adjacencies
(no hello packets sent/received). Use for:

- LAN segments with only hosts (no other OSPF routers)
- Interfaces where you want reachability advertised but no neighbors
- Security: prevents unexpected adjacencies on untrusted interfaces

**Terraform Example:**

```hcl
OSPF_JSON = jsonencode({
  enabled   = true
  router_id = "10.64.0.1"
  interfaces = [
    # Active OSPF on backbone links
    { name = "eth1", area = "0.0.0.0" },
    { name = "eth2", area = "0.0.0.0", cost = 100 },
    # Passive on LAN (advertise but no neighbors)
    { name = "eth3", area = "0.0.0.0", passive = true }
  ]
  redistribute = ["connected", "static"]
  default_information = {
    originate = true
    always    = true
    metric    = 100
  }
})
```

**Generated VyOS Commands:**

```text
set protocols ospf parameters router-id '10.64.0.1'
set protocols ospf interface eth1 area '0.0.0.0'
set protocols ospf interface eth2 area '0.0.0.0'
set protocols ospf interface eth2 cost '100'
set protocols ospf interface eth3 area '0.0.0.0'
set protocols ospf interface eth3 passive
set protocols ospf redistribute connected
set protocols ospf redistribute static
set protocols ospf default-information originate always
set protocols ospf default-information originate metric '100'
```

---

### DHCP_JSON

DHCP server configuration.

**Schema:**

```json
{
  "pools": [
    {
      "interface": "eth1",
      "subnet": "10.1.1.0/24",
      "range_start": "10.1.1.100",
      "range_end": "10.1.1.200",
      "gateway": "10.1.1.1",
      "dns": ["10.1.1.1", "8.8.8.8"],
      "lease_time": 86400,
      "domain": "example.local"
    }
  ],
  "reservations": [
    {
      "interface": "eth1",
      "mac": "00:11:22:33:44:55",
      "ip": "10.1.1.50",
      "hostname": "server01"
    }
  ]
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pools` | Array | No | DHCP pools |
| `pools[].interface` | String | Yes | Interface for this pool |
| `pools[].subnet` | CIDR | No | Subnet (auto-derived from interface if not set) |
| `pools[].range_start` | IP | Yes | First IP in range |
| `pools[].range_end` | IP | Yes | Last IP in range |
| `pools[].gateway` | IP | Yes | Default gateway for clients |
| `pools[].dns` | Array | Yes | DNS servers for clients |
| `pools[].lease_time` | Integer | No | Lease time in seconds |
| `pools[].domain` | String | No | Domain name for clients |
| `reservations` | Array | No | Static DHCP reservations |
| `reservations[].interface` | String | Yes | Interface for reservation |
| `reservations[].mac` | String | Yes | Client MAC address |
| `reservations[].ip` | IP | Yes | Reserved IP address |
| `reservations[].hostname` | String | No | Hostname for client |

**Terraform Example:**

```hcl
DHCP_JSON = jsonencode({
  pools = [
    {
      interface = "eth1"
      range_start = "10.61.0.64"
      range_end = "10.61.0.240"
      gateway = "10.61.0.1"
      dns = ["10.63.4.101"]
    }
  ]
  reservations = [
    {
      interface = "eth1"
      mac = "00:11:22:33:44:55"
      ip = "10.61.0.50"
      hostname = "printer01"
    }
  ]
})
```

---

### NAT_JSON

NAT configuration for source NAT (masquerading), destination NAT (port forwarding), and
bidirectional 1:1 NAT.

**Schema:**

```json
{
  "source": [
    {
      "outbound_interface": "eth1",
      "source_address": "10.0.0.0/8",
      "translation": "masquerade"
    },
    {
      "outbound_interface": "eth1",
      "source_address": "192.168.0.0/16",
      "translation_address": "203.0.113.10"
    }
  ],
  "destination": [
    {
      "inbound_interface": "eth1",
      "protocol": "tcp",
      "destination_port": 443,
      "translation_address": "10.62.0.20",
      "translation_port": 443,
      "description": "HTTPS to internal server"
    }
  ],
  "binat": [
    {
      "external_address": "129.244.246.66",
      "internal_address": "10.63.0.101",
      "interface": "eth0",
      "description": "Scoring engine"
    }
  ]
}
```

**Source NAT Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `outbound_interface` | String | Yes | Egress interface |
| `source_address` | CIDR | No | Source network to NAT |
| `translation` | String | Conditional | `masquerade` for dynamic SNAT |
| `translation_address` | IP/Range | Conditional | Static SNAT address |
| `description` | String | No | Rule description |

**Note:** Exactly one of `translation` or `translation_address` must be specified (they are
mutually exclusive).

**Destination NAT Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `inbound_interface` | String | Yes | Ingress interface |
| `protocol` | String | No | Protocol filter (see below) |
| `destination_address` | IP | No | Original destination (for 1:1 NAT) |
| `destination_port` | Integer | No | Original destination port (not valid for `icmp`) |
| `translation_address` | IP | Yes | New destination address |
| `translation_port` | Integer | No | New destination port |
| `description` | String | No | Rule description |

**Protocol values:**

| Value | Description |
|-------|-------------|
| `tcp` | TCP only |
| `udp` | UDP only |
| `tcp_udp` | Both TCP and UDP |
| `icmp` | ICMP only (port fields ignored) |
| *(omitted)* | All protocols (no filtering) |

**Bidirectional NAT (1:1) Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `external_address` | IP | Yes | External/public IP (must be alias on interface) |
| `internal_address` | IP | Yes | Internal IP to map to |
| `interface` | String | Yes | Interface where external IP is assigned |
| `description` | String | No | Rule description |

**Notes on Bidirectional NAT:**

- The `external_address` must be configured as a NIC alias in Terraform
- OpenNebula manages the IP lease; context provides it as `ETHx_ALIASy_IP`
- The contextualization script verifies the alias IP exists before creating NAT rules
- Creates both source and destination NAT rules for full bidirectional translation

**Terraform Example:**

```hcl
NAT_JSON = jsonencode({
  source = [
    {
      outbound_interface = "eth0"
      source_address = "10.0.0.0/8"
      translation = "masquerade"
    }
  ]
  destination = [
    {
      inbound_interface = "eth0"
      protocol = "tcp"
      destination_port = 443
      translation_address = "10.62.0.20"
      description = "HTTPS to web server"
    },
    {
      inbound_interface = "eth0"
      protocol = "tcp"
      destination_port = 2222
      translation_address = "10.62.0.30"
      translation_port = 22
      description = "SSH to jump host"
    }
  ]
  binat = [
    {
      external_address = "129.244.246.66"
      internal_address = "10.63.0.101"
      interface = "eth0"
      description = "Scoring engine"
    }
  ]
})
```

**Generated VyOS Commands:**

```
# Source NAT (masquerade)
set nat source rule 100 outbound-interface name 'eth0'
set nat source rule 100 source address '10.0.0.0/8'
set nat source rule 100 translation address 'masquerade'

# Destination NAT (port forwards)
set nat destination rule 100 inbound-interface name 'eth0'
set nat destination rule 100 protocol 'tcp'
set nat destination rule 100 destination port '443'
set nat destination rule 100 translation address '10.62.0.20'
set nat destination rule 100 description 'HTTPS to web server'

set nat destination rule 101 inbound-interface name 'eth0'
set nat destination rule 101 protocol 'tcp'
set nat destination rule 101 destination port '2222'
set nat destination rule 101 translation address '10.62.0.30'
set nat destination rule 101 translation port '22'
set nat destination rule 101 description 'SSH to jump host'

# Bidirectional NAT (1:1)
# Inbound: external -> internal
set nat destination rule 200 inbound-interface name 'eth0'
set nat destination rule 200 destination address '129.244.246.66'
set nat destination rule 200 translation address '10.63.0.101'
set nat destination rule 200 description 'Scoring engine'

# Outbound: internal -> external
set nat source rule 200 outbound-interface name 'eth0'
set nat source rule 200 source address '10.63.0.101'
set nat source rule 200 translation address '129.244.246.66'
set nat source rule 200 description 'Scoring engine'
```

---

### FIREWALL_JSON

Zone-based firewall configuration with groups, zones, and policies.

**Schema:**

```json
{
  "groups": {
    "network": {
      "GAME": ["10.64.0.0/10", "10.128.0.0/9"],
      "SCORING": ["10.62.0.0/16"],
      "OK_FROM_GAME": ["10.63.4.0/24", "10.61.0.0/23"]
    },
    "address": {
      "SCORING_ENGINE": ["10.63.0.101"],
      "DNS_SERVERS": ["10.63.4.101", "8.8.8.8"]
    },
    "port": {
      "WEB": [80, 443],
      "SSH": [22],
      "DNS": [53]
    }
  },
  "zones": {
    "WAN": {
      "interfaces": ["eth0"],
      "default_action": "drop"
    },
    "GAME": {
      "interfaces": ["eth1", "eth2"],
      "default_action": "drop"
    },
    "SCORING": {
      "interfaces": ["eth3"],
      "default_action": "drop"
    }
  },
  "policies": [
    {
      "from": "GAME",
      "to": "SCORING",
      "rules": [
        {
          "action": "accept",
          "protocol": "tcp",
          "destination_port_group": "WEB",
          "description": "Allow web traffic"
        }
      ]
    },
    {
      "from": "WAN",
      "to": "SCORING",
      "rules": [
        {
          "action": "accept",
          "destination_address_group": "SCORING_ENGINE",
          "description": "Allow NAT'd traffic to scoring"
        }
      ]
    },
    {
      "from": "SCORING",
      "to": "GAME",
      "rules": [
        {
          "action": "accept",
          "source_address_group": "SCORING_ENGINE",
          "description": "Scoring can reach game networks"
        }
      ]
    },
    {
      "from": "WAN",
      "to": "GAME",
      "rules": [
        {
          "action": "accept",
          "protocol": "icmp",
          "icmp_type": "echo-request",
          "description": "Allow ping from WAN to GAME"
        }
      ]
    }
  ]
}
```

**Groups Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `groups.network` | Object | Named network groups (CIDR notation) |
| `groups.address` | Object | Named address groups (individual IPs) |
| `groups.port` | Object | Named port groups (integers or ranges) |

**Zones Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `zones.<name>.interfaces` | Array | Yes | Interfaces belonging to this zone |
| `zones.<name>.default_action` | String | Yes | `drop` or `reject` (cannot be `accept`) |

**Policy Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | String | Yes | Source zone name |
| `to` | String | Yes | Destination zone name |
| `rules` | Array | Yes | List of rules for this zone pair |

**Rule Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | String | Yes | `accept`, `drop`, or `reject` |
| `protocol` | String | No | `tcp`, `udp`, `icmp`, or `tcp_udp` |
| `source_address` | String | No | Source IP or CIDR (inline) |
| `source_address_group` | String | No | Source address group name |
| `source_network_group` | String | No | Source network group name |
| `destination_address` | String | No | Destination IP or CIDR (inline) |
| `destination_address_group` | String | No | Destination address group name |
| `destination_network_group` | String | No | Destination network group name |
| `destination_port` | Integer/Array | No | Destination port(s) (inline) |
| `destination_port_group` | String | No | Destination port group name |
| `icmp_type` | String | No | ICMP type name (e.g., `echo-request`, `echo-reply`) |
| `description` | String | No | Rule description |

**Notes:**

- Interfaces not assigned to any zone bypass zone filtering (warning emitted)
- Management VRF interfaces should be left unzoned for open management access
- Global state policies (established/related/invalid) are automatically configured
- NAT happens before firewall; rules match post-NAT (internal) addresses
- Zone default_action applies when no policy rules match

**Terraform Example:**

```hcl
FIREWALL_JSON = jsonencode({
  groups = {
    network = {
      GAME     = ["10.64.0.0/10", "10.128.0.0/9"]
      SCORING  = ["10.62.0.0/16"]
    }
    address = {
      SCORING_ENGINE = ["10.63.0.101"]
    }
    port = {
      WEB = [80, 443]
    }
  }

  zones = {
    WAN = {
      interfaces     = ["eth0"]
      default_action = "drop"
    }
    GAME = {
      interfaces     = ["eth1"]
      default_action = "drop"
    }
    SCORING = {
      interfaces     = ["eth2"]
      default_action = "drop"
    }
  }

  policies = [
    {
      from = "GAME"
      to   = "SCORING"
      rules = [
        {
          action               = "accept"
          protocol             = "tcp"
          destination_port_group = "WEB"
          description          = "Game to scoring web"
        }
      ]
    },
    {
      from = "WAN"
      to   = "SCORING"
      rules = [
        {
          action                    = "accept"
          destination_address_group = "SCORING_ENGINE"
          description               = "NAT'd traffic to scoring engine"
        }
      ]
    },
    {
      from = "SCORING"
      to   = "GAME"
      rules = [
        {
          action              = "accept"
          source_address_group = "SCORING_ENGINE"
          description         = "Scoring engine can reach game"
        }
      ]
    },
    {
      from = "WAN"
      to   = "GAME"
      rules = [
        {
          action      = "accept"
          protocol    = "icmp"
          icmp_type   = "echo-request"
          description = "Allow ping from WAN"
        }
      ]
    }
  ]
})
```

**Generated VyOS Commands:**

```
# Global state policies
set firewall global-options state-policy established action accept
set firewall global-options state-policy related action accept
set firewall global-options state-policy invalid action drop

# Groups
set firewall group network-group GAME network '10.64.0.0/10'
set firewall group network-group GAME network '10.128.0.0/9'
set firewall group network-group SCORING network '10.62.0.0/16'
set firewall group address-group SCORING_ENGINE address '10.63.0.101'
set firewall group port-group WEB port 80
set firewall group port-group WEB port 443

# Zones
set firewall zone WAN interface eth0
set firewall zone WAN default-action drop
set firewall zone GAME interface eth1
set firewall zone GAME default-action drop
set firewall zone SCORING interface eth2
set firewall zone SCORING default-action drop

# Policy: GAME to SCORING
set firewall ipv4 name GAME-to-SCORING default-action drop
set firewall ipv4 name GAME-to-SCORING rule 100 action accept
set firewall ipv4 name GAME-to-SCORING rule 100 protocol tcp
set firewall ipv4 name GAME-to-SCORING rule 100 destination group port-group WEB
set firewall ipv4 name GAME-to-SCORING rule 100 description 'Game to scoring web'
set firewall zone SCORING from GAME firewall name GAME-to-SCORING

# Policy: WAN to SCORING
set firewall ipv4 name WAN-to-SCORING default-action drop
set firewall ipv4 name WAN-to-SCORING rule 100 action accept
set firewall ipv4 name WAN-to-SCORING rule 100 destination group address-group SCORING_ENGINE
set firewall ipv4 name WAN-to-SCORING rule 100 description 'NAT'd traffic to scoring engine'
set firewall zone SCORING from WAN firewall name WAN-to-SCORING

# Policy: SCORING to GAME
set firewall ipv4 name SCORING-to-GAME default-action drop
set firewall ipv4 name SCORING-to-GAME rule 100 action accept
set firewall ipv4 name SCORING-to-GAME rule 100 source group address-group SCORING_ENGINE
set firewall ipv4 name SCORING-to-GAME rule 100 description 'Scoring engine can reach game'
set firewall zone GAME from SCORING firewall name SCORING-to-GAME

# Policy: WAN to GAME (ICMP)
set firewall ipv4 name WAN-to-GAME default-action drop
set firewall ipv4 name WAN-to-GAME rule 100 action accept
set firewall ipv4 name WAN-to-GAME rule 100 protocol icmp
set firewall ipv4 name WAN-to-GAME rule 100 icmp type-name echo-request
set firewall ipv4 name WAN-to-GAME rule 100 description 'Allow ping from WAN'
set firewall zone GAME from WAN firewall name WAN-to-GAME
```

---

## Escape Hatch Variables

These variables allow arbitrary configuration when structured variables are insufficient.

### START_CONFIG

Raw VyOS commands executed within the configuration transaction.

| Variable | Type | Description |
|----------|------|-------------|
| `START_CONFIG` | String | VyOS commands (one per line; `set` prefix is optional) |

**Terraform Example:**

```hcl
START_CONFIG = <<-EOT
  set system option performance throughput
  set system syslog global facility all level info
EOT
```

**Notes:**

- Commands are executed after all structured configuration
- Commands run within the same transaction (atomic commit)
- Use for features not covered by JSON variables

### START_SCRIPT

Shell script executed after VyOS configuration is committed.

| Variable | Type | Description |
|----------|------|-------------|
| `START_SCRIPT` | String | Shell script content |

**Terraform Example:**

```hcl
START_SCRIPT = <<-EOT
  #!/bin/bash
  echo "Configuration complete at $(date)" >> /var/log/contextualization.log
EOT
```

**Notes:**

- Runs after `commit` succeeds
- Runs as root
- Use for non-VyOS configuration (custom files, external integrations)

---

## Complete Terraform Example

```hcl
resource "opennebula_virtual_machine" "router" {
  name        = "router-01"
  template_id = var.vyos_template_id

  # eth0 - Management
  nic {
    network_id = var.management_network_id
    ip         = "10.0.1.1"
  }

  # eth1 - WAN
  nic {
    network_id = var.wan_network_id
    ip         = "203.0.113.10"
  }

  # eth2 - LAN
  nic {
    network_id = var.lan_network_id
    ip         = "192.168.1.1"
  }

  context = {
    # Standard ONE variables
    NETWORK        = "YES"
    HOSTNAME       = "router-01"
    SSH_PUBLIC_KEY = "$USER[SSH_PUBLIC_KEY]"

    # Management interface (in VRF)
    ETH0_VROUTER_MANAGEMENT = "YES"

    # JSON extensions
    ROUTES_JSON = jsonencode({
      static = [
        { interface = "eth1", destination = "0.0.0.0/0", gateway = "203.0.113.1" }
      ]
    })

    OSPF_JSON = jsonencode({
      enabled = true
      areas = [
        { id = "0.0.0.0", networks = ["192.168.0.0/16"] }
      ]
      redistribute = ["connected"]
      passive_interfaces = ["eth1"]
    })

    NAT_JSON = jsonencode({
      source = [
        { outbound_interface = "eth1", source_address = "192.168.0.0/16", translation = "masquerade" }
      ]
    })

    DHCP_JSON = jsonencode({
      pools = [
        {
          interface = "eth2"
          range_start = "192.168.1.100"
          range_end = "192.168.1.200"
          gateway = "192.168.1.1"
          dns = ["192.168.1.1"]
        }
      ]
    })
  }
}
```

## Related Documentation

**Project documentation (mkdocs site):**

- [VyOS Router v3 Project](../../../../docs/docs/projects/active/vyos-router-v3/index.md) - Project overview and status
- [Implementation Plan](../../../../docs/docs/projects/active/vyos-router-v3/implementation-plan.md) - Phased implementation approach

**Technical reference:**

- [Design Document](design.md) - Architecture and design decisions

**Current production (Equuleus):**

- [VyOS Operator Guide](../../../../docs/docs/network/vyos_operator_guide.md) - Current Equuleus context variables (different format)

---

*This document was updated with assistance from Claude Code (Opus 4.5).*
