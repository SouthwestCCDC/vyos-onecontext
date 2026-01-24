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
- [Implementation Plan](../../../docs/docs/projects/active/vyos-router-v3/implementation-plan.md) - Phased implementation (path is relative to this repository when used as a submodule under the `deployment` repo and may not resolve when viewing this repository standalone)

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

## Code Review Guidelines

When reviewing pull requests, follow these guidelines to provide consistent, actionable feedback.

### Priority System

Categorize findings by severity:

- **CRITICAL** (blocks merge): VyOS syntax errors that would break router boot, security vulnerabilities, incorrect network configurations
- **IMPORTANT** (should fix before merge): Missing validation for context variables, inadequate test coverage, Pydantic model inconsistencies
- **SUGGESTION** (non-blocking): Code style improvements, documentation enhancements, refactoring opportunities

### Confidence Threshold

Only comment when HIGH CONFIDENCE (>80%) an issue exists. VyOS syntax can be subtle - if unsure whether something is correct for Sagitta, ask rather than assume.

### What CI Already Checks

Our CI pipeline handles:
- Python linting (`ruff`)
- Type checking (`mypy`)
- Unit tests (`pytest`)

**Do not duplicate feedback** on issues these tools catch. Focus on VyOS command correctness, context variable handling, and router configuration logic.

### VyOS-Specific Review Points

- **Sagitta syntax**: Verify commands use Sagitta 1.4.x syntax (see syntax differences in project docs)
- **Interface-based config**: NAT, routes should use `interface name 'X'` format
- **Stateless routers**: All config derives from context - no persistent state assumptions
- **Test fixtures**: New context patterns need corresponding test fixtures

### Security Focus

Flag these with **CRITICAL** priority:
- Firewall rules that could expose internal networks
- Missing input validation on context variables
- Incorrect zone assignments that bypass security boundaries

## MANDATORY: Be transparent about AI use

Disclose when AI generates content that humans will read and might attribute to a specific person.

**What requires disclosure:**
- GitHub issues and PR descriptions
- GitHub comments (on issues, PRs, or commits)
- Documentation files (markdown, READMEs, guides)
- Commit messages with substantive explanations

**How to disclose:**
- Commits: `Co-Authored-By:` line with AI identity
- Documentation/comments: brief closing sentence
- Include tool and model when known (e.g., "Claude Code w/ Opus 4.5")

**Exceptions (no disclosure needed):**
- Mechanical operations: git merge/rebase, conflict resolution
- Source code and config files
- Trivial changes: typo fixes, formatting
