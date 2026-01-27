# Commit Conventions

## Message Format

```
type(area): brief description

Addresses #ISSUE_NUMBER

Co-authored-by: {AI Tool/Model} <{AI email}>
```

## Types

| Type | Use For |
|------|---------|
| `feat` | New functionality |
| `fix` | Bug fixes |
| `refactor` | Code restructuring without behavior change |
| `test` | Adding or updating tests |
| `docs` | Documentation changes |
| `chore` | Build, CI, tooling changes |

## Areas

| Area | Scope |
|------|-------|
| `generator` | Configuration generators |
| `parser` | Context JSON parsing |
| `model` | Pydantic models |
| `cli` | Command-line interface |
| `test` | Test infrastructure |

## AI Disclosure

All AI-generated commits MUST include the co-author trailer:

```
Co-authored-by: {AI Tool/Model} <{AI email}>
```

Use tool-appropriate email domains:
- Claude (any model): `<noreply@anthropic.com>`
- GitHub Copilot: `<noreply@github.com>`
- Other tools: Use appropriate domain or `<{AI email}>` as placeholder

Examples: `Claude Sonnet 4.5`, `GitHub Copilot`, `Claude Opus 4.5`, etc.

## Examples

```
feat(generator): implement DHCP pool configuration

Adds support for parsing DHCP_JSON context variable and generating
VyOS DHCP server configuration.

Addresses #15

Co-authored-by: Claude Sonnet 4.5 <noreply@anthropic.com>
```

```
fix(parser): handle missing optional fields gracefully

Return default values instead of raising KeyError when optional
context fields are absent.

Addresses #23

Co-authored-by: GitHub Copilot <noreply@github.com>
```

---
*Generated with Claude Code assistance.*
