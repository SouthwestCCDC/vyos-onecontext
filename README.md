# vyos-onecontext

OpenNebula contextualization for VyOS Sagitta (1.4.x) router images.

## Overview

This repository provides scripts that configure VyOS routers at boot time based on
OpenNebula context variables. Routers are stateless - all configuration derives from
context on every boot.

## Documentation

- [Design Document](docs/design.md) - Architecture and design decisions
- [Context Variable Reference](docs/context-reference.md) - All supported variables with examples

## Branches

- **sagitta** - VyOS Sagitta (1.4.x LTS) - active development
- **legacy/equuleus** - VyOS Equuleus (1.3.x) - maintenance only, EOL upstream

## Quick Start

Context variables are set in your OpenNebula VM template or Terraform configuration:

```hcl
context = {
  NETWORK        = "YES"
  HOSTNAME       = "router-01"
  SSH_PUBLIC_KEY = "$USER[SSH_PUBLIC_KEY]"

  # Management interface in VRF
  ETH0_VROUTER_MANAGEMENT = "YES"

  # Static routes (JSON format)
  ROUTES_JSON = jsonencode({
    static = [
      { interface = "eth1", destination = "0.0.0.0/0", gateway = "10.0.1.254" }
    ]
  })

  # OSPF (JSON format)
  OSPF_JSON = jsonencode({
    enabled = true
    areas = [{ id = "0.0.0.0", networks = ["10.0.0.0/8"] }]
    redistribute = ["connected", "static"]
  })
}
```

See the [Context Variable Reference](docs/context-reference.md) for all options.

## Features

**Designed (implementation pending):**
- Interface configuration (standard OpenNebula variables)
- NIC aliases / secondary IPs (OpenNebula NIC alias support)
- Management VRF (OpenNebula vrouter convention)
- Static routing
- OSPF with authentication and passive interfaces
- DHCP server with pools and reservations
- Source NAT (masquerading)
- Destination NAT (port forwarding)
- Bidirectional 1:1 NAT (using NIC aliases for external IPs)
- Zone-based firewall (groups, zones, policies)
- Custom VyOS commands (escape hatch)

**Out of scope:**
- VLAN-tagged interfaces (OpenNebula provides virtual NICs)
- VPN (handled by dedicated infrastructure)
- Captive portal, schedule-based rules

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management:

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Lint
uv run ruff check .

# Format
uv run ruff format .

# Type check
uv run mypy src/
```

Or use the justfile:

```bash
just test      # Run tests
just lint      # Run linter
just fmt       # Format code
just check     # Run all checks
```

## Related

**Project documentation (in deployment/docs/docs/):**

- [VyOS Router v3 Project](../../../docs/docs/projects/active/vyos-router-v3/index.md) - Project overview and status
- [Implementation Plan](../../../docs/docs/projects/active/vyos-router-v3/implementation-plan.md) - Phased implementation approach
- [Requirements](../../../docs/docs/projects/active/vyos-router-v3/requirements.md) - Detailed requirements analysis

**External:**

- [deployment](https://github.com/SouthwestCCDC/deployment) - Packer builds and infrastructure
- [VyOS Sagitta Documentation](https://docs.vyos.io/en/sagitta/)
