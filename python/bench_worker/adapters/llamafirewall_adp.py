"""Meta LlamaFirewall adapter (Prompt Guard 2 86M + CodeShield).

Implementation notes (see ARCHITECTURE.md):
  - Sets TOKENIZERS_PARALLELISM=true to avoid HuggingFace fork warnings.
  - Pre-checks ~/.cache/huggingface and HF_TOKEN during Health RPCs rather than
    triggering interactive model downloads mid-benchmark.
  - Maps request.role (user/system/assistant/tool) cleanly to LlamaFirewall Role enums.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
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

os.environ.setdefault("TOKENIZERS_PARALLELISM", "true")

DEFAULT_PROMPT_GUARD_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"


@dataclass(frozen=True)
class LlamaFirewallScanOutcome:
    blocked: bool
    score: float
    categories: tuple[str, ...]
    spans: tuple[SpanSpec, ...] = ()


# Lightweight deterministic mock mirroring Prompt Guard 2 trigger sensitivity + CodeShield.
_IMPERATIVE_INJECTION_RE = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|rules)|"
    r"disregard\s+(?:all\s+)?safety|system\s+override|\[assistant\s+instruction\]|"
    r"unrestricted\s+(?:developer|maintenance|compliance)\s+mode|"
    r"reveal\s+(?:the\s+)?(?:hidden\s+)?system\s+prompt|"
    r"print\s+(?:the\s+)?(?:exact|full)\s+(?:system|developer))\b"
)
_TRIGGER_WORDS_RE = re.compile(
    r"(?i)\b(?:ignore\s+previous|system\s+prompt|bypass|override|jailbreak|"
    r"prompt\s+injection|developer\s+mode|disregard|act\s+as|reveal)\b"
)
_INSECURE_CODE_RE = re.compile(
    r"(?m)(?:^def\s+[A-Za-z_]\w*\s*\([^\n]*\)|^func\s+[A-Za-z_]\w*\s*\([^\n]*\)|"
    r"\b(?:eval|exec|subprocess\.Popen)\s*\()"
)


def mock_llamafirewall_scan(role: str, text: str, history_len: int) -> LlamaFirewallScanOutcome:
    """Deterministic offline mock for unit tests and CI without Meta HF weights.

    Simulates Prompt Guard 2's high sensitivity to injection keywords (including
    occasional trigger-word over-defense on 3-trigger NotInject prompts) plus
    CodeShield detection on code snippets.
    """
    del history_len
    categories: list[str] = []
    score = 0.04
    blocked = False
    spans: list[SpanSpec] = []

    if _IMPERATIVE_INJECTION_RE.search(text):
        blocked = True
        score = 0.96
        categories.append(f"prompt_guard_2_{role.lower() or 'user'}")
    else:
        triggers = _TRIGGER_WORDS_RE.findall(text)
        if len(triggers) >= 3:
            # Known trigger-word bias baseline on dense 3-trigger NotInject benign inputs.
            blocked = True
            score = 0.72
            categories.append("prompt_guard_2_trigger_dense")
        elif len(triggers) == 2:
            score = 0.34
        elif len(triggers) == 1:
            score = 0.16

    for match in _INSECURE_CODE_RE.finditer(text):
        spans.append(
            SpanSpec(
                entity_type="SOURCE_CODE",
                begin_offset=match.start(),
                end_offset=match.end(),
                confidence=0.85,
            )
        )
        categories.append("codeshield_code_pattern")
        score = max(score, 0.85)
        blocked = True

    return LlamaFirewallScanOutcome(
        blocked=blocked,
        score=score,
        categories=tuple(sorted(set(categories))),
        spans=tuple(spans),
    )


def _hf_model_cached(model_id: str, cache_dir: Path | None = None) -> bool:
    hub_dir = cache_dir or (
        Path(os.environ.get("HF_HOME", str(Path.home() / ".cache" / "huggingface"))) / "hub"
    )
    folder_name = "models--" + model_id.replace("/", "--")
    model_dir = hub_dir / folder_name
    return model_dir.exists() and any(model_dir.iterdir())


class LlamaFirewallAdapter(GuardrailAdapter):
    """Plane 2 adapter wrapping Meta LlamaFirewall (Prompt Guard 2 + CodeShield)."""

    def __init__(
        self,
        *,
        model_id: str = DEFAULT_PROMPT_GUARD_MODEL,
        use_mock: bool = False,
        scanner: Callable[[str, str, int], LlamaFirewallScanOutcome] | None = None,
        hf_cache_dir: Path | None = None,
        threshold: float = 0.50,
    ) -> None:
        self.adapter_name = "llamafirewall"
        self.model_version = f"{model_id}{'-mock' if use_mock else ''}"
        self._model_id = model_id
        self._use_mock = use_mock
        self._scanner = scanner
        self._hf_cache_dir = hf_cache_dir
        self._threshold = threshold
        self._sessions: dict[str, list[tuple[str, str]]] = {}
        self._live_firewall: Any | None = None

    async def health(self) -> tuple[str, str]:
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "true")
        if self._use_mock or self._scanner is not None:
            return (self.adapter_name, self.model_version)

        # Pre-check HuggingFace cache and HF_TOKEN so we never trigger interactive downloads.
        cached = _hf_model_cached(self._model_id, self._hf_cache_dir)
        has_token = bool(os.environ.get("HF_TOKEN", "").strip())
        if not cached and not has_token:
            raise RuntimeError(
                f"LlamaFirewall model {self._model_id!r} not found in HuggingFace cache and "
                "HF_TOKEN is unset. Pre-download weights or pass --mock for offline testing."
            )
        self._ensure_live_firewall()
        return (self.adapter_name, self.model_version)

    def _ensure_live_firewall(self) -> Any:
        if self._live_firewall is not None:
            return self._live_firewall
        try:
            from llamafirewall import (  # type: ignore[import-not-found]
                LlamaFirewall,
                Role,
                ScannerType,
            )
        except ImportError as exc:
            raise RuntimeError(
                "llamafirewall package not installed. Install with: uv sync --extra oss"
            ) from exc
        self._live_firewall = LlamaFirewall(
            scanners={
                Role.USER: [ScannerType.PROMPT_GUARD],
                Role.SYSTEM: [ScannerType.PROMPT_GUARD],
                Role.TOOL: [ScannerType.PROMPT_GUARD],
                Role.ASSISTANT: [ScannerType.CODE_SHIELD],
            }
        )
        return self._live_firewall

    async def reset_session(self, session_id: str) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    async def evaluate(
        self, request: adapter_pb2.EvaluateRequest
    ) -> adapter_pb2.EvaluateResponse:
        start = time.perf_counter()
        role = (request.role or "user").strip().lower()
        history = self._sessions.setdefault(request.session_id, []) if request.session_id else []
        history_len = len(history)
        if request.session_id:
            history.append((role, request.text))

        if self._scanner is not None:
            outcome = self._scanner(role, request.text, history_len)
        elif self._use_mock:
            outcome = mock_llamafirewall_scan(role, request.text, history_len)
        else:
            outcome = self._run_live_scan(role, request.text)

        spans = normalize_spans(request.text, outcome.spans)
        redacted = apply_span_redactions(request.text, spans)
        wall_ms = (time.perf_counter() - start) * 1000.0

        return adapter_pb2.EvaluateResponse(
            blocked=outcome.blocked,
            risk_score=float(max(0.0, min(1.0, outcome.score))),
            redacted_text=redacted,
            spans=to_proto_spans(spans),
            triggered_categories=sorted(set(outcome.categories)),
            taint_state=adapter_pb2.SessionTaint(),
            usage=compute_usage_metrics(request.text, wall_ms),
            judge_graded=False,
        )

    def _run_live_scan(self, role: str, text: str) -> LlamaFirewallScanOutcome:
        from llamafirewall import (
            AssistantMessage,
            ScanDecision,
            SystemMessage,
            ToolMessage,
            UserMessage,
        )

        fw = self._ensure_live_firewall()
        if role == "system":
            msg = SystemMessage(content=text)
        elif role == "tool":
            msg = ToolMessage(content=text)
        elif role == "assistant":
            msg = AssistantMessage(content=text)
        else:
            msg = UserMessage(content=text)

        res = fw.scan(msg)
        score = float(getattr(res, "score", 0.0))
        blocked = getattr(res, "decision", None) == ScanDecision.BLOCK or score >= self._threshold
        reason = str(getattr(res, "reason", "") or "")
        cats = (f"llamafirewall:{reason}",) if blocked and reason else (
            ("llamafirewall_block",) if blocked else ()
        )
        return LlamaFirewallScanOutcome(blocked=blocked, score=score, categories=cats)
