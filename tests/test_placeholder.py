"""Placeholder test to verify test framework is working."""


def test_placeholder() -> None:
    """Verify pytest is working."""
    assert True


def test_package_import() -> None:
    """Verify the package can be imported."""
    import vyos_onecontext

    assert vyos_onecontext.__version__ == "0.1.0"
