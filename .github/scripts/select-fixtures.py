#!/usr/bin/env python3
"""
Select integration test fixtures based on changed files.

This script reads the test mapping configuration and determines which
integration test fixtures should run based on the files that have changed.

Additionally, it detects newly-added fixtures (added to TEST_SCENARIOS in
run-all-tests.sh) and automatically includes them in the selection, ensuring
new fixtures always run in PR CI.

Usage:
    select-fixtures.py <base-ref> <head-ref>

Arguments:
    base-ref: Git reference for the base (e.g., origin/sagitta)
    head-ref: Git reference for the head (e.g., HEAD)

Outputs:
    Space-separated list of fixture names (without .env extension),
    "all" to indicate all fixtures should run,
    or empty string when no changed files or new fixtures are detected.

Exit codes:
    0: Success
    1: Error (invalid arguments, git errors, etc.)
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]


def get_changed_files(base_ref: str, head_ref: str) -> list[str]:
    """Get list of files changed between two git refs."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...{head_ref}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to get changed files: {e}", file=sys.stderr)
        print(f"stderr: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def load_mapping(mapping_file: Path) -> dict[str, Any]:
    """Load the test mapping configuration."""
    try:
        with open(mapping_file) as f:
            return cast(dict[str, Any], yaml.safe_load(f))
    except FileNotFoundError:
        print(f"ERROR: Mapping file not found: {mapping_file}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"ERROR: Invalid YAML in mapping file: {e}", file=sys.stderr)
        sys.exit(1)


def extract_test_scenarios(content: str) -> set[str]:
    """
    Extract fixture names from TEST_SCENARIOS array in run-all-tests.sh.

    Parses lines like: "simple:Simple router" to extract "simple".

    Returns:
        Set of fixture names.

    Raises:
        SystemExit: If content is non-empty but TEST_SCENARIOS array not found.

    Notes:
        Prints a warning (but continues) if array is found but no fixtures parsed.
    """
    fixtures = set()

    # Track whether we found the array declaration
    found_array = False

    # Match lines like: "simple:Simple router"
    # Between declare -a TEST_SCENARIOS=( and )
    in_array = False
    for line in content.splitlines():
        if "TEST_SCENARIOS=(" in line:
            in_array = True
            found_array = True
            continue
        if in_array and line.strip() == ")":
            break
        if in_array:
            # Extract fixture name from "name:description" pattern
            match = re.match(r'\s*"([^:]+):', line)
            if match:
                fixtures.add(match.group(1))

    # Validate parsing results
    if content and not found_array:
        print(
            "ERROR: Failed to find TEST_SCENARIOS array in run-all-tests.sh",
            file=sys.stderr,
        )
        print(
            "The array syntax may have changed or the file structure was modified.",
            file=sys.stderr,
        )
        sys.exit(1)

    if found_array and not fixtures:
        print(
            "WARNING: TEST_SCENARIOS array found but no fixtures parsed.",
            file=sys.stderr,
        )
        print(
            "This may indicate a parsing failure or empty array (suspicious).",
            file=sys.stderr,
        )

    return fixtures


def get_file_content_at_ref(file_path: str, git_ref: str) -> str:
    """Get file content at a specific git reference."""
    try:
        result = subprocess.run(
            ["git", "show", f"{git_ref}:{file_path}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # File might not exist at this ref (new file)
        if "does not exist" in e.stderr or "exists on disk, but not in" in e.stderr:
            return ""
        print(
            f"ERROR: Failed to get {file_path} at {git_ref}: {e}",
            file=sys.stderr,
        )
        print(f"stderr: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_newly_added_fixtures(base_ref: str, head_ref: str) -> set[str]:
    """
    Detect fixtures newly added to TEST_SCENARIOS.

    Compares TEST_SCENARIOS array between base and head refs.

    Returns:
        Set of newly-added fixture names.
    """
    test_script = "tests/integration/run-all-tests.sh"

    # Get TEST_SCENARIOS at base and head
    base_content = get_file_content_at_ref(test_script, base_ref)
    head_content = get_file_content_at_ref(test_script, head_ref)

    base_fixtures = extract_test_scenarios(base_content) if base_content else set()
    head_fixtures = extract_test_scenarios(head_content) if head_content else set()

    # New fixtures are in head but not in base
    new_fixtures = head_fixtures - base_fixtures

    return new_fixtures


def get_all_mapped_fixtures(mapping: dict[str, Any]) -> set[str]:
    """
    Get all fixture names that appear in the mapping configuration.

    Returns:
        Set of all fixture names referenced in mappings (excluding "all").
    """
    all_fixtures = set()
    for entry in mapping.get("mappings", []):
        fixtures = entry.get("fixtures", [])
        for fixture in fixtures:
            if fixture != "all":
                all_fixtures.add(fixture)
    return all_fixtures


def warn_unmapped_fixtures(all_fixtures: set[str], mapped_fixtures: set[str]) -> None:
    """
    Warn about fixtures that exist but have no mapping.

    Prints warnings to stderr for fixtures in TEST_SCENARIOS that don't
    appear in any mapping entry.
    """
    unmapped = all_fixtures - mapped_fixtures
    if unmapped:
        print("#", file=sys.stderr)
        print(
            "# WARNING: Unmapped fixtures (no mapping in test-mapping.yml):",
            file=sys.stderr,
        )
        for fixture in sorted(unmapped):
            print(f"#   {fixture}", file=sys.stderr)
        print(
            "# These fixtures will only run if matched by default or 'all' patterns,",
            file=sys.stderr,
        )
        print(
            "# OR if they are newly added in this PR. Newly-added fixtures run automatically",
            file=sys.stderr,
        )
        print(
            "# but should still be mapped for future selective test runs.",
            file=sys.stderr,
        )
        print("#", file=sys.stderr)


def select_fixtures(changed_files: list[str], mapping: dict[str, Any]) -> set[str]:
    """
    Select fixtures to run based on changed files and mapping.

    Returns set of fixture names, or {"all"} if all fixtures should run.
    """
    if not changed_files:
        # No changes = no tests needed (though this shouldn't happen in CI)
        return set()

    fixtures = set()

    for file in changed_files:
        matched = False
        for entry in mapping.get("mappings", []):
            pattern = entry.get("pattern")
            if pattern and Path(file).match(pattern):
                matched = True
                entry_fixtures = entry.get("fixtures", [])

                # If any mapping says "all", we need all fixtures
                if "all" in entry_fixtures:
                    return {"all"}

                fixtures.update(entry_fixtures)

        # If a file doesn't match any pattern, use the default
        if not matched:
            default = mapping.get("default", ["all"])
            if "all" in default:
                return {"all"}
            fixtures.update(default)

    return fixtures


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select integration test fixtures based on changed files"
    )
    parser.add_argument("base_ref", help="Base git reference (e.g., origin/sagitta)")
    parser.add_argument(
        "head_ref", help="Head git reference (e.g., HEAD)", nargs="?", default="HEAD"
    )
    parser.add_argument(
        "--mapping-file",
        type=Path,
        default=Path(__file__).parent.parent / "test-mapping.yml",
        help="Path to test mapping configuration (default: .github/test-mapping.yml)",
    )

    args = parser.parse_args()

    # Load mapping first (for unmapped fixture warnings)
    mapping = load_mapping(args.mapping_file)

    # Get changed files
    changed_files = get_changed_files(args.base_ref, args.head_ref)

    # Detect newly-added fixtures
    new_fixtures = get_newly_added_fixtures(args.base_ref, args.head_ref)

    if new_fixtures:
        print("#", file=sys.stderr)
        print(f"# Newly-added fixtures ({len(new_fixtures)}):", file=sys.stderr)
        for f in sorted(new_fixtures):
            print(f"#   {f}", file=sys.stderr)
        print("# These will be automatically included in the test run.", file=sys.stderr)
        print("#", file=sys.stderr)

    if not changed_files and not new_fixtures:
        print("# No changed files or new fixtures detected", file=sys.stderr)
        print("")  # Empty output = no fixtures
        return

    if changed_files:
        print(f"# Changed files ({len(changed_files)}):", file=sys.stderr)
        for f in changed_files[:10]:  # Show first 10
            print(f"#   {f}", file=sys.stderr)
        if len(changed_files) > 10:
            print(f"#   ... and {len(changed_files) - 10} more", file=sys.stderr)
        print("#", file=sys.stderr)

    # Select fixtures based on changed files
    fixtures = select_fixtures(changed_files, mapping)

    # Add newly-added fixtures to the selection
    fixtures.update(new_fixtures)

    # Check for unmapped fixtures and warn
    # Get all fixtures from current HEAD
    test_script_content = get_file_content_at_ref(
        "tests/integration/run-all-tests.sh", args.head_ref
    )
    all_fixtures = extract_test_scenarios(test_script_content)
    mapped_fixtures = get_all_mapped_fixtures(mapping)
    warn_unmapped_fixtures(all_fixtures, mapped_fixtures)

    if not fixtures:
        print("# No fixtures selected", file=sys.stderr)
        print("")
        return

    if "all" in fixtures:
        print("# Running ALL fixtures (core files changed)", file=sys.stderr)
        print("all")
    else:
        print(f"# Running {len(fixtures)} fixture(s):", file=sys.stderr)
        for f in sorted(fixtures):
            print(f"#   {f}", file=sys.stderr)
        print("#", file=sys.stderr)
        print(" ".join(sorted(fixtures)))


if __name__ == "__main__":
    main()
