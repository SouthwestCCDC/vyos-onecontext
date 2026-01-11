# vyos-onecontext

OpenNebula contextualization scripts for VyOS router images.

## Project Context

This repo provides scripts that run at VM boot to configure VyOS routers based on OpenNebula context variables. The scripts read from a context CD mounted at boot and apply network, routing, NAT, and service configuration.

## Branches

- **main** - VyOS sagitta (1.4.x LTS) target
- **legacy/equuleus** - VyOS equuleus (1.3.x), maintenance only

## VyOS Version

Target version: **sagitta 1.4.x LTS**

Key differences from equuleus:
- NAT interface syntax: `outbound-interface name 'eth0'` (not bare `eth0`)
- Static routes: `route X interface Y` (not `interface-route X next-hop-interface Y`)
- Firewall zones: `firewall zone` (not `zone-policy zone`)
- NTP uses chrony, requires explicit `allow-client` for server mode
- Native cloud-init support via `vyos_config_commands`

## Testing

Contextualization scripts should have bats-core tests. Test against actual VyOS sagitta images in OpenNebula.

## Related Repos

- **deployment** - Packer image builds, Terraform infrastructure
- **scoring** - Uses vrouter-relay images for scoring infrastructure
