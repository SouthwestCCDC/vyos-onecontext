# vyos-onecontext

OpenNebula contextualization for VyOS Sagitta (1.4.x) router images.

## Project Context

This repo provides a hybrid shell + Python system that configures VyOS routers at boot based on
OpenNebula context variables. Routers are stateless by default - all configuration derives from
context on every boot.

**Architecture:**
- Shell entry point for systemd integration and VyOS `vbash` execution
- Python package (`vyos_onecontext`) for JSON parsing, validation, and config generation
- Pydantic models for schema validation
- Generators output VyOS command strings; shell executes them

## Branches

- **sagitta** - VyOS Sagitta (1.4.x LTS) - active development
- **legacy/equuleus** - VyOS Equuleus (1.3.x) - maintenance only

## Documentation

- [Design Document](docs/design.md) - Architecture and design decisions
- [Context Variable Reference](docs/context-reference.md) - All supported variables with examples
- [Implementation Plan](../../../docs/docs/projects/active/vyos-router-v3/implementation-plan.md) - Phased implementation

## VyOS Version

Target version: **Sagitta 1.4.x LTS**

Key syntax differences from Equuleus (interface-based config preferred in Sagitta):
- NAT interface: `outbound-interface name 'eth0'` (not bare `eth0`)
- Static routes: `route X interface Y` (not `interface-route X next-hop-interface Y`)
- Firewall zones: `firewall zone` (not `zone-policy zone`)
- OSPF: `interface X area Y` (not `area Y network X`)
- NTP uses chrony, requires explicit `allow-client` for server mode

## Development

```bash
uv sync              # Install dependencies
uv run pytest        # Run tests
uv run ruff check .  # Lint
uv run mypy src/     # Type check
just check           # Run all checks
```

## Related Repos

- **deployment** - Packer image builds (submodule at `packer/opennebula-context/vyos-sagitta`)
- **scoring** - Uses vrouter-relay images for scoring infrastructure
