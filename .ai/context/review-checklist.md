# Review Checklist

Use this checklist when reviewing PRs or pre-commit changes.

## Code Quality

- [ ] Clear, readable code with meaningful names
- [ ] Appropriate error handling and edge cases
- [ ] Follows existing patterns in the codebase
- [ ] Type hints present on public functions

## VyOS Specific

- [ ] Correct VyOS Sagitta syntax (NOT Equuleus)
- [ ] Commands tested against actual VyOS Sagitta
- [ ] No deprecated VyOS features used
- [ ] Configuration paths match VyOS hierarchy

## Testing

- [ ] Tests cover new functionality
- [ ] Edge cases handled (missing fields, malformed input)
- [ ] Pytest tests pass: `uv run pytest tests/ -v`

## Security

- [ ] No hardcoded credentials or secrets
- [ ] Input validation present
- [ ] Context variables sanitized

## AI Disclosure

- [ ] Commits have `Co-authored-by: Claude {Model} <noreply@anthropic.com>`
- [ ] PR description mentions AI assistance if applicable

## Assessment Categories

| Assessment | Meaning |
|------------|---------|
| **Ready to merge** | All checks pass, no blocking issues |
| **Needs fixes** | Issues found that must be addressed |
| **Needs discussion** | Architectural or scope questions to resolve |

---
*Generated with Claude Code assistance.*
