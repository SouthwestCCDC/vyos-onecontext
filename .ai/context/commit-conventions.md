# Commit Conventions

## Message Format

```
type(area): brief description

Addresses #ISSUE_NUMBER

Co-Authored-By: Claude {Model} <noreply@anthropic.com>
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
Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

Use the actual model (Sonnet 4.5, Opus 4.5, Haiku, etc.).

## Examples

```
feat(generator): implement DHCP pool configuration

Adds support for parsing DHCP_JSON context variable and generating
VyOS DHCP server configuration.

Addresses #15

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

```
fix(parser): handle missing optional fields gracefully

Return default values instead of raising KeyError when optional
context fields are absent.

Addresses #23

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```
