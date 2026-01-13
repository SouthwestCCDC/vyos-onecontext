#!/usr/bin/env python3
"""Quick manual test of parser fixes."""

import sys
sys.path.insert(0, 'src')

from vyos_onecontext.parser import ContextParser
from pathlib import Path
import tempfile

def test_escaped_quotes():
    """Test escaped quote handling."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write('TEST="value with \\"quote\\""\n')
        f.flush()

        parser = ContextParser(f.name)
        parser._read_variables()

        result = parser.variables.get("TEST")
        expected = 'value with "quote"'

        print(f"Test escaped quotes:")
        print(f"  Expected: {repr(expected)}")
        print(f"  Got:      {repr(result)}")
        print(f"  PASS" if result == expected else f"  FAIL")
        print()

        Path(f.name).unlink()
        return result == expected

def test_whitespace_only():
    """Test whitespace-only unquoted value."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write("TEST=   \n")
        f.flush()

        parser = ContextParser(f.name)
        parser._read_variables()

        result = parser.variables.get("TEST")
        expected = ""

        print(f"Test whitespace-only unquoted:")
        print(f"  Expected: {repr(expected)}")
        print(f"  Got:      {repr(result)}")
        print(f"  PASS" if result == expected else f"  FAIL")
        print()

        Path(f.name).unlink()
        return result == expected

def test_escaped_backslash():
    """Test escaped backslash."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write('TEST="path\\\\to\\\\file"\n')
        f.flush()

        parser = ContextParser(f.name)
        parser._read_variables()

        result = parser.variables.get("TEST")
        expected = "path\\to\\file"

        print(f"Test escaped backslash:")
        print(f"  Expected: {repr(expected)}")
        print(f"  Got:      {repr(result)}")
        print(f"  PASS" if result == expected else f"  FAIL")
        print()

        Path(f.name).unlink()
        return result == expected

if __name__ == "__main__":
    results = []
    results.append(test_escaped_quotes())
    results.append(test_whitespace_only())
    results.append(test_escaped_backslash())

    print(f"\nOverall: {'ALL PASS' if all(results) else 'SOME FAILED'}")
    sys.exit(0 if all(results) else 1)
