"""NVIDIA NeMo Guardrails + Microsoft Presidio PII span & anonymization adapter."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Sequence
from typing import Any

from bench_worker.adapters.base import (
    GuardrailAdapter,
    SpanSpec,
    apply_span_redactions,
    compute_usage_metrics,
    normalize_spans,
    to_proto_spans,
)
from bench_worker.gen.bench.v1 import adapter_pb2

_PRESIDIO_LABEL_MAP: dict[str, str] = {
    "EMAIL_ADDRESS": "EMAIL",
    "US_SSN": "SSN",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "CREDIT_CARD": "CREDIT_CARD",
    "PERSON": "PERSON",
    "IP_ADDRESS": "IP_ADDRESS",
    "AWS_ACCESS_KEY": "AWS_ACCESS_KEY",
}

_MOCK_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), 0.97),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.94),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]){3}\d{4}\b"), 0.92),
    (
        "PHONE_NUMBER",
        re.compile(
            r"(?:\+1-555-\d{4}\b|\+?\d{1,3}[-\s.]?\(?\d{3}\)?[-\s.]\d{3}[-\s.]\d{4}\b)"
        ),
        0.90,
    ),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.99),
    # Recognizes capitalized person names in synthetic PII fixtures including accented characters.
    (
        "PERSON",
        re.compile(r"\b(?:Jordan Canary|José Nuñez|Alice Canary|Bob Example)\b"),
        0.91,
    ),
)


def mock_presidio_analyze(text: str) -> list[SpanSpec]:
    """Deterministic offline Presidio-compatible analyzer for CI and unit tests."""
    spans: list[SpanSpec] = []
    for entity_type, pattern, confidence in _MOCK_PATTERNS:
        for m in pattern.finditer(text):
            spans.append(
                SpanSpec(
                    entity_type=entity_type,
                    begin_offset=m.start(),
                    end_offset=m.end(),
                    confidence=confidence,
                )
            )
    # Remove phone matches that overlap SSN or credit cards.
    normed = normalize_spans(text, spans)
    filtered: list[SpanSpec] = []
    for sp in normed:
        if sp.entity_type == "PHONE_NUMBER" and any(
            prev.entity_type in ("SSN", "CREDIT_CARD")
            and sp.begin_offset < prev.end_offset
            and prev.begin_offset < sp.end_offset
            for prev in filtered
        ):
            continue
        filtered.append(sp)
    return filtered


class NemoPresidioAdapter(GuardrailAdapter):
    """Plane 2 adapter combining Presidio character-offset NER/PII spans and optional NeMo rails."""

    def __init__(
        self,
        *,
        use_mock: bool = False,
        enable_dialog_rails: bool = False,
        rails_config_path: str | None = None,
        analyzer_fn: Callable[[str], Sequence[SpanSpec]] | None = None,
        dialog_rail_fn: Callable[[str, list[dict[str, str]]], tuple[bool, float, list[str]]]
        | None = None,
        language: str = "en",
    ) -> None:
        self.adapter_name = "nemo_presidio"
        mode_tag = "mock" if use_mock else ("rails+presidio" if enable_dialog_rails else "presidio")
        self.model_version = f"nemo-presidio-2.2-{mode_tag}"
        self._use_mock = use_mock
        self._enable_dialog_rails = enable_dialog_rails
        self._rails_config_path = rails_config_path
        self._analyzer_fn = analyzer_fn
        self._dialog_rail_fn = dialog_rail_fn
        self._language = language
        self._sessions: dict[str, list[dict[str, str]]] = {}
        self._live_analyzer: Any | None = None
        self._live_rails: Any | None = None

    async def health(self) -> tuple[str, str]:
        if self._use_mock or self._analyzer_fn is not None:
            return (self.adapter_name, self.model_version)
        self._ensure_live_presidio()
        if self._enable_dialog_rails:
            self._ensure_live_rails()
        return (self.adapter_name, self.model_version)

    def _ensure_live_presidio(self) -> Any:
        if self._live_analyzer is not None:
            return self._live_analyzer
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "presidio-analyzer not installed. Install with: uv sync --extra oss"
            ) from exc
        self._live_analyzer = AnalyzerEngine()
        return self._live_analyzer

    def _ensure_live_rails(self) -> Any:
        if self._live_rails is not None:
            return self._live_rails
        try:
            from nemoguardrails import LLMRails, RailsConfig  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "nemoguardrails not installed. Install with: uv sync --extra oss"
            ) from exc
        if not self._rails_config_path:
            raise RuntimeError("rails_config_path is required when enable_dialog_rails=True")
        cfg = RailsConfig.from_path(self._rails_config_path)
        self._live_rails = LLMRails(cfg)
        return self._live_rails

    async def reset_session(self, session_id: str) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    async def evaluate(
        self, request: adapter_pb2.EvaluateRequest
    ) -> adapter_pb2.EvaluateResponse:
        start = time.perf_counter()

        history = self._sessions.setdefault(request.session_id, []) if request.session_id else []
        if request.session_id:
            history.append({"role": request.role or "user", "content": request.text})

        if self._analyzer_fn is not None:
            raw_spans = list(self._analyzer_fn(request.text))
        elif self._use_mock:
            raw_spans = mock_presidio_analyze(request.text)
        else:
            raw_spans = self._run_live_presidio(request.text)

        spans = normalize_spans(request.text, raw_spans)
        redacted = apply_span_redactions(request.text, spans)

        categories: set[str] = {f"presidio_{sp.entity_type}" for sp in spans}
        blocked = len(spans) > 0
        score = max((sp.confidence for sp in spans), default=0.02)
        judge_graded = False

        if self._enable_dialog_rails:
            judge_graded = True
            if self._dialog_rail_fn is not None:
                rail_blocked, rail_score, rail_cats = self._dialog_rail_fn(
                    request.text, list(history)
                )
            elif self._use_mock:
                rail_blocked, rail_score, rail_cats = (False, 0.05, [])
            else:
                rail_blocked, rail_score, rail_cats = await self._run_live_rails(list(history))
            blocked = blocked or rail_blocked
            score = max(score, rail_score)
            categories.update(rail_cats)

        wall_ms = (time.perf_counter() - start) * 1000.0
        return adapter_pb2.EvaluateResponse(
            blocked=blocked,
            risk_score=float(max(0.0, min(1.0, score))),
            redacted_text=redacted,
            spans=to_proto_spans(spans),
            triggered_categories=sorted(categories),
            taint_state=adapter_pb2.SessionTaint(),
            usage=compute_usage_metrics(request.text, wall_ms),
            judge_graded=judge_graded,
        )

    def _run_live_presidio(self, text: str) -> list[SpanSpec]:
        engine = self._ensure_live_presidio()
        results = engine.analyze(text=text, language=self._language)
        spans: list[SpanSpec] = []
        for item in results:
            mapped = _PRESIDIO_LABEL_MAP.get(str(item.entity_type), str(item.entity_type))
            spans.append(
                SpanSpec(
                    entity_type=mapped,
                    begin_offset=int(item.start),
                    end_offset=int(item.end),
                    confidence=float(item.score),
                )
            )
        return spans

    async def _run_live_rails(
        self, messages: list[dict[str, str]]
    ) -> tuple[bool, float, list[str]]:
        rails = self._ensure_live_rails()
        reply = await rails.generate_async(messages=messages)
        content = str(reply.get("content", "") if isinstance(reply, dict) else reply)
        refused = "i'm sorry, i can't" in content.lower() or "cannot comply" in content.lower()
        return (refused, 0.90 if refused else 0.05, ["nemo_dialog_rail"] if refused else [])
