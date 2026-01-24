---
applyTo: "**/*.sh"
---

# Shell Script Guidelines

## VyOS Integration
- Scripts run inside VyOS `vbash` environment
- Use `source /opt/vyatta/etc/functions/script-template` for VyOS functions
- Commands execute via `vyos_onecontext_run` wrapper

## Error Handling
- Check command exit codes
- Log errors to syslog for debugging
- Fail gracefully - partial config is better than boot failure

## Systemd Integration
- Entry point script runs as systemd service
- Must complete before network-online.target
- Keep execution time minimal for fast boot

## ShellCheck
- All scripts must pass shellcheck
- Use `shellcheck disable=SCXXXX` comments sparingly and with justification
