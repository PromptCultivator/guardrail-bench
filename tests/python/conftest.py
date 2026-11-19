"""Pytest configuration adding `--live` flag to gate live model and AWS integration tests."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Run integration tests requiring live HuggingFace weights, vLLM, or AWS credentials.",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--live"):
        return
    skip_live = pytest.mark.skip(reason="pass --live to execute live model/cloud integration tests")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
