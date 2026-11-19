"""Abstract adapter interface and deterministic helpers for Plane 2 Python workers.

Normalized output semantics align with mozilla-ai/any-guardrail's GuardrailOutput
(`valid`, `score`, `categories`, `usage`), extended with UTF-8 character-offset spans
and stateful MCP session taint.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from bench_worker.gen.bench.v1 import adapter_pb2


@dataclass(frozen=True)
class SpanSpec:
    """Character-offset sensitive span [begin_offset, end_offset) over Python str (UTF-8 runes)."""

    entity_type: str
    begin_offset: int
    end_offset: int
    confidence: float = 1.0


def compute_usage_metrics(text: str, wall_ms: float) -> adapter_pb2.UsageMetrics:
    """Computes deterministic character, Bedrock text-unit, token, and wall-time metrics."""
    input_chars = len(text)
    text_units = max(1, math.ceil(input_chars / 1000)) if input_chars > 0 else 1
    input_tokens = (input_chars + 3) // 4 if input_chars > 0 else 0
    return adapter_pb2.UsageMetrics(
        input_chars=input_chars,
        text_units_billed=text_units,
        input_tokens=input_tokens,
        adapter_wall_ms=wall_ms,
    )


def normalize_spans(text: str, spans: Sequence[SpanSpec]) -> list[SpanSpec]:
    """Validates bounds, deduplicates, and deterministically sorts UTF-8 character spans."""
    text_len = len(text)
    valid = [
        sp
        for sp in spans
        if sp.entity_type and 0 <= sp.begin_offset < sp.end_offset <= text_len
    ]
    valid.sort(
        key=lambda s: (
            s.begin_offset,
            -s.end_offset,
            -s.confidence,
            s.entity_type,
        )
    )
    dedup: list[SpanSpec] = []
    seen: set[tuple[int, int, str]] = set()
    for sp in valid:
        key = (sp.begin_offset, sp.end_offset, sp.entity_type)
        if key not in seen:
            seen.add(key)
            dedup.append(sp)
    return dedup


def apply_span_redactions(text: str, spans: Sequence[SpanSpec]) -> str:
    """Deterministically masks non-overlapping spans with `[REDACTED:<ENTITY_TYPE>]`."""
    ordered = normalize_spans(text, spans)
    if not ordered:
        return text

    parts: list[str] = []
    cursor = 0
    for sp in ordered:
        if sp.begin_offset < cursor:
            continue
        parts.append(text[cursor : sp.begin_offset])
        parts.append(f"[REDACTED:{sp.entity_type}]")
        cursor = sp.end_offset
    if cursor < len(text):
        parts.append(text[cursor:])
    return "".join(parts)


def to_proto_spans(spans: Sequence[SpanSpec]) -> list[adapter_pb2.SpanFinding]:
    """Converts SpanSpec objects to protobuf SpanFinding messages."""
    return [
        adapter_pb2.SpanFinding(
            entity_type=sp.entity_type,
            begin_offset=sp.begin_offset,
            end_offset=sp.end_offset,
            confidence=sp.confidence,
        )
        for sp in spans
    ]


class GuardrailAdapter(ABC):
    """Base contract implemented by all Plane 2 Python guardrail adapters."""

    adapter_name: str
    model_version: str

    @abstractmethod
    async def health(self) -> tuple[str, str]:
        """Validates adapter readiness (caches/creds/endpoints) without downloading weights."""

    @abstractmethod
    async def evaluate(
        self, request: adapter_pb2.EvaluateRequest
    ) -> adapter_pb2.EvaluateResponse:
        """Evaluates a single request/turn and returns a normalized EvaluateResponse."""

    @abstractmethod
    async def reset_session(self, session_id: str) -> None:
        """Clears any per-session conversational or taint state associated with session_id."""
