---
applyTo: "**/*.py"
---

# Python Code Guidelines

## Type Hints
- All functions in `src/` must have type hints (CI runs `mypy src/` with `disallow_untyped_defs = true`)
- Use Pydantic models for context variable validation
- Generator functions return `list[str]` (VyOS commands)

## Pydantic Models
- Models in `src/vyos_onecontext/models/`
- Use validators for complex context variable parsing
- JSON context variables (e.g., `DHCP_JSON`) need careful validation

## Generator Pattern
- Generators in `src/vyos_onecontext/generators/`
- Each generator handles one aspect of VyOS config
- Generators output VyOS command strings, shell executes them
- Commands must be valid VyOS Sagitta 1.4.x syntax

## Testing
- Test fixtures represent real OpenNebula context scenarios
- New context patterns need corresponding test fixtures
- Validate generated commands against expected VyOS syntax
