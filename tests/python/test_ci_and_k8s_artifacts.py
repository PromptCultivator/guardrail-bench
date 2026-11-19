"""Verification tests for CI workflow, baseline artifact, docs, and Envoy policy."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_pinned_smoke_baseline_schema_and_invariants() -> None:
    baseline_path = (
        REPO_ROOT / "datasets" / "baselines" / "trifecta_extproc_smoke_50.score.json"
    )
    doc: dict[str, Any] = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert doc["adapter_name"] == "trifecta_extproc"
    assert doc["total_samples"] == 50
    assert doc["stability"]["verdict_flip_rate"] == 0
    assert doc["track1_injection"]["recall_at_1pct_fpr"]["recall"]["point"] == 1
    assert doc["track1_injection"]["notinject"]["accuracy"]["point"] == 1
    assert doc["track3_mcp_trifecta"]["trifecta_block_rate"] == 1
    assert doc["track3_mcp_trifecta"]["safe_pass_rate"] == 1
    assert doc["judge_separation"]["evaluation_mode"] == "deterministic"


def test_github_ci_workflow_enforces_pr_regression_gates() -> None:
    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for required in (
        "make proto",
        "go test -race",
        "uv run ruff check",
        "uv run mypy --strict",
        "uv run pytest",
        "guardrail-bench gate",
        "--max-recall-drop 0.01",
        "--max-p99-regression 0.15",
        "--require-zero-vfr",
        "datasets/baselines/trifecta_extproc_smoke_50.score.json",
        "make envoy-test",
    ):
        assert required in ci_text, f".github/workflows/ci.yml missing {required!r}"


def test_envoy_extension_policy_upstream_artifact() -> None:
    policy_text = (
        REPO_ROOT / "deployments" / "envoy" / "envoy-extension-policy.yaml"
    ).read_text(encoding="utf-8")
    for required in (
        "apiVersion: gateway.envoyproxy.io/v1alpha1",
        "kind: EnvoyExtensionPolicy",
        "kind: BackendTrafficPolicy",
        "appProtocol: kubernetes.io/h2c",
        "port: 9002",
        "failOpen: false",
        "allowModeOverride: true",
        "--max-decode-depth=3",
        "--max-decoded-bytes=1048576",
    ):
        assert required in policy_text, f"envoy-extension-policy.yaml missing {required!r}"


def test_readme_adr_sections_and_no_latex_math() -> None:
    assert not (REPO_ROOT / "PLAN.md").exists(), "PLAN.md should be removed"
    assert not (REPO_ROOT / "AGENTS.md").exists(), "AGENTS.md should be removed"

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    for heading in (
        "## Highlights",
        "## Quick Start",
        "## Installation",
        "## Usage",
        "## CLI & Supported Adapters",
        "## Benchmark Highlights",
        "## Architecture & System Invariants",
        "## Scope, Non-Goals & Known Limitations",
        "## Contributing & Support",
        "## License",
    ):
        assert heading in readme, f"README.md missing section {heading!r}"

    architecture = (REPO_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    for section in (
        "Two-Plane Hybrid Architecture",
        "Canonical Data Contracts",
        "Evaluation Tracks, Evasion Mutators & Decontamination",
        "Native Go Core (`pkg/trifecta`) & Envoy `ext_proc` Baseline",
        "Target Guardrail Adapters & Implementation Decisions",
        "CLI Reference, Mathematical Scoring & CI Gate",
    ):
        assert section in architecture, f"ARCHITECTURE.md missing section {section!r}"

    benchmarks = (REPO_ROOT / "BENCHMARKS.md").read_text(encoding="utf-8")
    for section in (
        "Live Pre-Flight Decontamination Findings",
        "Live Full-Corpus Benchmark",
        "Live Envoy `ext_proc` Proxy Latency",
        "`pkg/trifecta` Go Micro-Benchmarks",
        "Annualized TCO Projections",
    ):
        assert section in benchmarks, f"BENCHMARKS.md missing section {section!r}"

    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    for section in (
        "Prerequisites & Local Toolchain",
        "Engineering Invariants",
        "Adapter Testing Conventions",
        "Standard Verification Commands",
    ):
        assert section in contributing, f"CONTRIBUTING.md missing section {section!r}"

    forbidden_pattern = re.compile(
        r"Milestone\s+\d|PLAN\.md|AGENTS\.md|Coding-agent|PromptFence"
        r"|You are building|previous prompt"
    )
    latex_pattern = re.compile(r"\\(?:frac|sum|ge|le|mathbb|bigcup|bigcap)\b")

    for name, content in (
        ("README.md", readme),
        ("ARCHITECTURE.md", architecture),
        ("BENCHMARKS.md", benchmarks),
        ("CONTRIBUTING.md", contributing),
    ):
        # Enforce Unicode math rule (no LaTeX $$ display blocks or LaTeX math commands).
        assert "$$" not in content, f"{name} must not contain LaTeX $$ blocks"
        assert not latex_pattern.search(content), f"{name} must use Unicode math, not LaTeX"
        assert not forbidden_pattern.search(content), (
            f"{name} contains forbidden design-evolution or prompt reference"
        )
