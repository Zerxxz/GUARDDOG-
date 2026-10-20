"""Smoke test: core deps import and versions are sane."""

import web3


def test_web3_imports():
    assert web3.__version__.startswith("8.")


def test_package_layout():
    import sentinel  # noqa: F401
    import leash  # noqa: F401
