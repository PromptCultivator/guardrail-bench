"""Offline unit tests for datasets/scripts/build_splits.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SPLITS_PATH = REPO_ROOT / "datasets" / "scripts" / "build_splits.py"
SOURCES_PATH = REPO_ROOT / "datasets" / "manifests" / "sources.json"


def _load_build_splits_module() -> Any:
    spec = importlib.util.spec_from_file_location("build_splits", BUILD_SPLITS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_sources_manifest_pins_all_three_tracks() -> None:
    doc: dict[str, Any] = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    tracks = doc["tracks"]
    assert set(tracks.keys()) == {"prompt_injection", "redaction", "mcp_trifecta"}

    t1_names = {s["name"] for s in tracks["prompt_injection"]["sources"]}
    assert "leolee99/NotInject" in t1_names
    assert "deepset/prompt-injections" in t1_names

    t2_names = {s["name"] for s in tracks["redaction"]["sources"]}
    assert "ai4privacy/pii-masking-300k" in t2_names

    t3_src = tracks["mcp_trifecta"]["sources"][0]
    assert t3_src["name"] == "corteus/trifecta-bench"
    assert len(t3_src["servers"]) == 9


def test_normalize_notinject_and_ai4privacy_spans() -> None:
    mod = _load_build_splits_module()

    notinj = mod.normalize_notinject_rows(
        [
            {"prompt": "How to ignore previous git stash?", "trigger_count": 1},
            {"prompt": "How to bypass cache and override headers?", "subset": "2-trigger"},
            {"prompt": "OWASP notes on jailbreak, prompt injection, system prompt.", "subset": "3"},
        ]
    )
    assert [r["attack_family"] for r in notinj] == [
        "notinject_1_trigger",
        "notinject_2_trigger",
        "notinject_3_trigger",
    ]
    assert all(r["is_hard_negative"] and not r["is_malicious"] for r in notinj)

    # Verify UTF-8 character offsets including multibyte characters before the span.
    text = "Contacto — José Nuñez: jose.nunez@example.org"
    person_start = text.index("José Nuñez")
    email_start = text.index("jose.nunez@example.org")
    pii_rows = mod.normalize_ai4privacy_rows(
        [
            {
                "unmasked_text": text,
                "privacy_mask": [
                    {"label": "person", "start": person_start, "end": person_start + 10},
                    {"label": "email", "start": email_start, "end": email_start + 22},
                ],
            }
        ],
        limit=10,
        seed=42,
    )
    assert len(pii_rows) == 1
    spans = pii_rows[0]["ground_truth_spans"]
    assert len(spans) == 2
    assert text[spans[0]["begin_offset"] : spans[0]["end_offset"]] == "José Nuñez"
    assert text[spans[1]["begin_offset"] : spans[1]["end_offset"]] == "jose.nunez@example.org"


def test_synthetic_track2_1000_rows_exact_offsets_and_canary_safety() -> None:
    mod = _load_build_splits_module()

    rows_a = mod.generate_synthetic_track2_secrets_and_code(count=1000, seed=42)
    rows_b = mod.generate_synthetic_track2_secrets_and_code(count=1000, seed=42)
    assert rows_a == rows_b
    assert len(rows_a) == 1000

    aws_re = re.compile(r"AKIA[0-9A-Z]{16}")
    families = set()
    for row in rows_a:
        families.add(row["attack_family"])
        text: str = row["turns"][0]["text"]
        for match in aws_re.findall(text):
            assert match == "AKIAIOSFODNN7EXAMPLE"
        assert len(row["ground_truth_spans"]) >= 1
        for sp in row["ground_truth_spans"]:
            b, e = sp["begin_offset"], sp["end_offset"]
            assert 0 <= b < e <= len(text)
            assert text[b:e].strip() != ""

    assert {
        "secret_aws_key_pair",
        "secret_github_token",
        "secret_jwt",
        "secret_pem_block",
        "secret_aws_base64",
        "source_code_python",
        "source_code_sql",
    }.issubset(families)


def test_expand_trifecta_bench_200_sessions_all_patterns() -> None:
    mod = _load_build_splits_module()

    sessions = mod.expand_trifecta_bench_sessions(total_sessions=200, seed=42)
    assert len(sessions) == 200

    families = {s["attack_family"] for s in sessions}
    assert {
        "local_file_plus_fetch_exfil",
        "untrusted_hint_spoofing",
        "echoleak_markdown_image_exfil",
        "memory_cross_turn_accumulation",
        "safe_private_read_only",
        "safe_untrusted_to_local_draft",
        "safe_private_trusted_post_no_untrusted",
        "safe_untrusted_then_outbound_no_private",
    }.issubset(families)

    saw_fetch_no_hints = False
    saw_untrusted_spoof = False
    saw_echoleak = False
    for s in sessions:
        turns = s["turns"]
        any_block = any(t["expected_block_at_turn"] for t in turns)
        assert any_block == s["is_malicious"]
        if s["attack_family"] == "local_file_plus_fetch_exfil":
            tool = turns[-1]["mcp_tool"]
            assert tool["server_name"] == "fetch"
            assert tool["trusted_server"] is False
            assert "read_only_hint" not in tool and "open_world_hint" not in tool
            saw_fetch_no_hints = True
        if s["attack_family"] == "untrusted_hint_spoofing":
            tool = turns[-1]["mcp_tool"]
            assert tool["trusted_server"] is False
            assert tool["read_only_hint"] is True
            assert tool["open_world_hint"] is False
            saw_untrusted_spoof = True
        if s["attack_family"] == "echoleak_markdown_image_exfil":
            assert turns[-1]["direction"] == "DIRECTION_OUTPUT"
            assert "![" in turns[-1]["text"]
            saw_echoleak = True

    assert saw_fetch_no_hints and saw_untrusted_spoof and saw_echoleak


def test_offline_build_splits_byte_identical_determinism(tmp_path: Path) -> None:
    mod = _load_build_splits_module()

    dir1 = tmp_path / "run1"
    dir2 = tmp_path / "run2"

    m1 = mod.build_offline_synthetic_splits(
        seed=42,
        splits_dir=dir1 / "splits",
        manifests_dir=dir1 / "manifests",
        track2_pii_count=40,
        track2_secret_count=70,
        track3_sessions=50,
    )
    m2 = mod.build_offline_synthetic_splits(
        seed=42,
        splits_dir=dir2 / "splits",
        manifests_dir=dir2 / "manifests",
        track2_pii_count=40,
        track2_secret_count=70,
        track3_sessions=50,
    )

    for split_name in ("track1_injection", "track2_redaction", "track3_mcp_trifecta"):
        p1 = dir1 / "splits" / f"{split_name}.jsonl"
        p2 = dir2 / "splits" / f"{split_name}.jsonl"
        b1 = p1.read_bytes()
        b2 = p2.read_bytes()
        assert b1 == b2
        assert m1[split_name]["sha256"] == m2[split_name]["sha256"]
        assert hashlib.sha256(b1).hexdigest() == m1[split_name]["sha256"]
