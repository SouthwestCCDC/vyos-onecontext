#!/usr/bin/env python3
"""
Select integration test fixtures based on changed files.

This script reads the test mapping configuration and determines which
integration test fixtures should run based on the files that have changed.

Usage:
    select-fixtures.py <base-ref> <head-ref>

Arguments:
    base-ref: Git reference for the base (e.g., origin/sagitta)
    head-ref: Git reference for the head (e.g., HEAD)

Outputs:
    Space-separated list of fixture names (without .env extension)
    or "all" to indicate all fixtures should run.

Exit codes:
    0: Success
    1: Error (invalid arguments, git errors, etc.)
"""

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path
from typing import Set

import yaml


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


def load_mapping(mapping_file: Path) -> dict:
    """Load the test mapping configuration."""
    try:
        with open(mapping_file) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"ERROR: Mapping file not found: {mapping_file}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"ERROR: Invalid YAML in mapping file: {e}", file=sys.stderr)
        sys.exit(1)


def select_fixtures(changed_files: list[str], mapping: dict) -> Set[str]:
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
            if pattern and fnmatch.fnmatch(file, pattern):
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


def main():
    parser = argparse.ArgumentParser(
        description="Select integration test fixtures based on changed files"
    )
    parser.add_argument(
        "base_ref", help="Base git reference (e.g., origin/sagitta)"
    )
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

    # Get changed files
    changed_files = get_changed_files(args.base_ref, args.head_ref)

    if not changed_files:
        print("# No changed files detected", file=sys.stderr)
        print("")  # Empty output = no fixtures
        return

    print(f"# Changed files ({len(changed_files)}):", file=sys.stderr)
    for f in changed_files[:10]:  # Show first 10
        print(f"#   {f}", file=sys.stderr)
    if len(changed_files) > 10:
        print(f"#   ... and {len(changed_files) - 10} more", file=sys.stderr)
    print("#", file=sys.stderr)

    # Load mapping and select fixtures
    mapping = load_mapping(args.mapping_file)
    fixtures = select_fixtures(changed_files, mapping)

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
