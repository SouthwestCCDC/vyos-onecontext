# vyos-onecontext

OpenNebula contextualization for VyOS Sagitta (1.4.x) router images.

## Overview

This project provides a Python-based contextualization system that configures VyOS
routers at boot time based on OpenNebula context variables. Routers are stateless by
default -- all configuration is derived from context on every boot, ensuring consistent
state without drift.

**How it works:**

1. OpenNebula attaches a context ISO containing shell variables to the VM
2. At boot, the VyOS boot hook invokes the Python contextualization module
3. Context variables are parsed and validated using Pydantic models
4. VyOS CLI commands are generated and executed via `vyatta-cfg-cmd-wrapper`
5. Configuration is committed (but not saved in stateless mode)

## Features

**Implemented (Phase 0):**

- Interface configuration with primary IP addresses
- NIC aliases (secondary IPs for 1:1 NAT scenarios)
- MTU configuration
- Hostname and SSH public key setup
- Context parsing with multi-line value support
- Pydantic models with comprehensive validation
- Cross-reference validation (interfaces referenced by NAT, DHCP, OSPF, etc.)
- Operational modes: stateless (default), save, freeze
- START_SCRIPT execution after commit

**Designed (models ready, generators in progress):**

- Management VRF interface placement
- Static routing with VRF support
- OSPF dynamic routing (interface-based, Sagitta syntax)
- DHCP server (pools and reservations)
- Source NAT (masquerading)
- Destination NAT (port forwarding)
- Bidirectional 1:1 NAT
- Zone-based firewall (groups, zones, policies)
- START_CONFIG (raw VyOS commands)

**Out of scope:**

- VLAN-tagged interfaces (OpenNebula provides virtual NICs)
- VPN (handled by dedicated infrastructure)
- HA/VRRP, IPv6, captive portal

## Development Setup

### Prerequisites

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/) package manager
- [just](https://github.com/casey/just) command runner (optional but recommended)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/SouthwestCCDC/vyos-onecontext.git
cd vyos-onecontext

# Install dependencies
uv sync

# Run all checks (lint, typecheck, test)
just check
```

### Available Commands

Using `just` (recommended):

```bash
just check      # Run all checks (lint, typecheck, test)
just test       # Run tests only
just lint       # Run ruff linter
just typecheck  # Run mypy type checker
just fmt        # Format code with ruff
just fmt-check  # Check formatting without changes
just install    # Install dependencies
just update     # Update dependencies
```

Or directly with `uv run`:

```bash
uv run pytest              # Run tests
uv run ruff check src/     # Lint
uv run ruff format src/    # Format
uv run mypy src/           # Type check
```

## Project Structure

```
vyos-onecontext/
├── src/vyos_onecontext/
│   ├── __init__.py          # Package exports
│   ├── __main__.py          # CLI entry point
│   ├── parser.py            # Context file parsing
│   ├── wrapper.py           # VyOS CLI wrapper
│   ├── models/              # Pydantic data models
│   │   ├── config.py        # RouterConfig (top-level)
│   │   ├── interface.py     # Interface and alias models
│   │   ├── routing.py       # Static routes and OSPF
│   │   ├── dhcp.py          # DHCP server
│   │   ├── nat.py           # NAT rules
│   │   └── firewall.py      # Zone-based firewall
│   └── generators/          # VyOS command generators
│       ├── base.py          # Base generator class
│       ├── system.py        # Hostname, SSH keys
│       └── interface.py     # Interface configuration
├── tests/
│   ├── fixtures/            # Test context files
│   ├── test_models.py       # Model validation tests
│   ├── test_parser.py       # Context parsing tests
│   ├── test_generators.py   # Command generation tests
│   └── ...
├── docs/
│   ├── design.md            # Architecture and design decisions
│   └── context-reference.md # Context variable documentation
├── scripts/                  # Boot hook scripts for VyOS image
├── pyproject.toml           # Project configuration
├── justfile                 # Task automation
└── uv.lock                  # Pinned dependencies
```

## Documentation

- [Design Document](docs/design.md) - Architecture, operational model, and design decisions
- [Context Variable Reference](docs/context-reference.md) - Complete reference for all
  supported context variables with examples

## Usage

Context variables are set in your OpenNebula VM template or Terraform configuration:

```hcl
context = {
  NETWORK        = "YES"
  HOSTNAME       = "router-01"
  SSH_PUBLIC_KEY = "$USER[SSH_PUBLIC_KEY]"

  # Management interface in VRF
  ETH0_VROUTER_MANAGEMENT = "YES"

  # Static routes (JSON)
  ROUTES_JSON = jsonencode({
    static = [
      { interface = "eth1", destination = "0.0.0.0/0", gateway = "10.0.1.254" }
    ]
  })

  # NAT (JSON)
  NAT_JSON = jsonencode({
    source = [
      { outbound_interface = "eth1", source_address = "10.0.0.0/8", translation = "masquerade" }
    ]
  })
}
```

See [Context Variable Reference](docs/context-reference.md) for all supported variables.

## Branches

- **sagitta** - VyOS Sagitta (1.4.x LTS) - active development
- **legacy/equuleus** - VyOS Equuleus (1.3.x) - maintenance only, EOL upstream

## Related

- [VyOS Sagitta Documentation](https://docs.vyos.io/en/sagitta/)
- [OpenNebula Contextualization](https://docs.opennebula.io/6.8/management_and_operations/references/template.html#context-section)

---

*This README was generated with assistance from Claude Code (Opus 4.5).*
