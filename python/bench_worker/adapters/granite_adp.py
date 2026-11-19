"""IBM Granite Guardian 3.3 / 4.1 8B adapter via OpenAI-compatible vLLM API.

Supports both:
  - Fast non-thinking mode (`thinking_mode=False`): extracts calibrated risk score
    from Yes/No token logprobs `P(Yes) / (P(Yes) + P(No))`.
  - Thinking-trace mode (`thinking_mode=True`): parses `<think>...</think>` +
    `<score>yes|no</score>` including tool-call hallucination (`function_call`) risk.

Always marks `judge_graded=True` per System Invariant #4.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
import urllib.request
from collections.abc import Awaitable, Callable
from typing import Any

from bench_worker.adapters.base import (
    GuardrailAdapter,
    compute_usage_metrics,
)
from bench_worker.gen.bench.v1 import adapter_pb2

DEFAULT_GRANITE_MODEL = "ibm-granite/granite-guardian-4.1-8b"
DEFAULT_VLLM_BASE_URL = "http://127.0.0.1:8000"

HttpPostFn = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
HttpGetFn = Callable[[str], Awaitable[dict[str, Any]]]

_SCORE_TAG_RE = re.compile(r"(?is)<score>\s*(yes|no)\s*</score>")
_ATTACK_HINT_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"system\s+override|attacker\.example|disregard\s+all\s+safety|"
    r"unrestricted\s+.*mode|\[assistant\s+instruction\])"
)


def parse_yes_no_logprob_score(choice: dict[str, Any]) -> float:
    """Computes calibrated P(Yes) / (P(Yes) + P(No)) from OpenAI chat completion logprobs."""
    logprobs = choice.get("logprobs")
    if isinstance(logprobs, dict):
        content_lps = logprobs.get("content")
        if isinstance(content_lps, list) and content_lps:
            first_tok = content_lps[0]
            top_lps = first_tok.get("top_logprobs") if isinstance(first_tok, dict) else None
            if isinstance(top_lps, list):
                p_yes = 0.0
                p_no = 0.0
                for entry in top_lps:
                    if not isinstance(entry, dict):
                        continue
                    tok = str(entry.get("token", "")).strip().lower()
                    lp = float(entry.get("logprob", -100.0))
                    prob = math.exp(max(-50.0, min(0.0, lp)))
                    if tok == "yes":
                        p_yes += prob
                    elif tok == "no":
                        p_no += prob
                denom = p_yes + p_no
                if denom > 0.0:
                    return max(0.0, min(1.0, p_yes / denom))

    # Fallback to generated token text if logprobs were omitted.
    msg = choice.get("message")
    text = str(msg.get("content", "") if isinstance(msg, dict) else "").strip().lower()
    if text.startswith("yes"):
        return 0.95
    if text.startswith("no"):
        return 0.05
    return 0.50


def parse_thinking_trace_verdict(content: str) -> tuple[bool, float]:
    """Parses Granite Guardian thinking-trace output `<think>...</think><score>yes|no</score>`."""
    m = _SCORE_TAG_RE.search(content)
    if m:
        is_risky = m.group(1).lower() == "yes"
        return (is_risky, 0.92 if is_risky else 0.06)
    lowered = content.strip().lower()
    if lowered.endswith("yes") or "\nyes" in lowered:
        return (True, 0.85)
    return (False, 0.08)


async def mock_vllm_post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Deterministic offline mock mimicking vLLM OpenAI /v1/chat/completions."""
    del url
    messages = payload.get("messages", [])
    last_text = str(messages[-1].get("content", "")) if messages else ""
    extra = payload.get("extra_body", {})
    thinking = bool(extra.get("chat_template_kwargs", {}).get("think", False))
    risky = bool(_ATTACK_HINT_RE.search(last_text))

    if thinking:
        verdict = "yes" if risky else "no"
        reasoning = (
            "Detected prompt injection or unauthorized external tool exfiltration."
            if risky
            else "No policy violation or tool-call hallucination detected."
        )
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"<think>{reasoning}</think>\n<score>{verdict}</score>",
                    }
                }
            ]
        }

    lp_yes, lp_no = (-0.05, -3.0) if risky else (-3.2, -0.04)
    return {
        "choices": [
            {
                "message": {"role": "assistant", "content": "Yes" if risky else "No"},
                "logprobs": {
                    "content": [
                        {
                            "token": "Yes" if risky else "No",
                            "logprob": lp_yes if risky else lp_no,
                            "top_logprobs": [
                                {"token": "Yes", "logprob": lp_yes},
                                {"token": "No", "logprob": lp_no},
                            ],
                        }
                    ]
                },
            }
        ]
    }


async def mock_vllm_get(url: str) -> dict[str, Any]:
    del url
    return {"data": [{"id": DEFAULT_GRANITE_MODEL}]}


class GraniteGuardianAdapter(GuardrailAdapter):
    """Plane 2 adapter wrapping IBM Granite Guardian 3.3 / 4.1 8B via vLLM OpenAI API."""

    def __init__(
        self,
        *,
        model_id: str = DEFAULT_GRANITE_MODEL,
        base_url: str = DEFAULT_VLLM_BASE_URL,
        thinking_mode: bool = False,
        threshold: float = 0.50,
        use_mock: bool = False,
        http_post: HttpPostFn | None = None,
        http_get: HttpGetFn | None = None,
        timeout_sec: float = 15.0,
    ) -> None:
        self.adapter_name = "granite_guardian"
        mode_tag = "thinking" if thinking_mode else "fast"
        self.model_version = f"{model_id}-{mode_tag}{'-mock' if use_mock else ''}"
        self._model_id = model_id
        self._base_url = base_url.rstrip("/")
        self._thinking_mode = thinking_mode
        self._threshold = threshold
        self._use_mock = use_mock
        self._http_post = http_post or (mock_vllm_post if use_mock else self._default_http_post)
        self._http_get = http_get or (mock_vllm_get if use_mock else self._default_http_get)
        self._timeout_sec = timeout_sec
        self._sessions: dict[str, list[dict[str, str]]] = {}

    async def health(self) -> tuple[str, str]:
        data = await self._http_get(f"{self._base_url}/v1/models")
        models = data.get("data", [])
        if not isinstance(models, list) or not models:
            raise RuntimeError(f"vLLM endpoint {self._base_url} reported zero loaded models")
        return (self.adapter_name, self.model_version)

    async def reset_session(self, session_id: str) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    async def evaluate(
        self, request: adapter_pb2.EvaluateRequest
    ) -> adapter_pb2.EvaluateResponse:
        start = time.perf_counter()

        risk_criterion = self._select_criterion(request)
        history = self._sessions.setdefault(request.session_id, []) if request.session_id else []
        role = request.role or "user"
        msg = {"role": role, "content": request.text}
        messages = [*history, msg]
        if request.session_id:
            history.append(msg)

        payload: dict[str, Any] = {
            "model": self._model_id,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 256 if self._thinking_mode else 1,
            "logprobs": not self._thinking_mode,
            "top_logprobs": 5 if not self._thinking_mode else None,
            "extra_body": {
                "chat_template_kwargs": {
                    "guardian_config": {"risk_name": risk_criterion},
                    "think": self._thinking_mode,
                }
            },
        }
        if payload["top_logprobs"] is None:
            del payload["top_logprobs"]

        raw = await self._http_post(f"{self._base_url}/v1/chat/completions", payload)
        choices = raw.get("choices", [])
        choice: dict[str, Any] = choices[0] if isinstance(choices, list) and choices else {}

        if self._thinking_mode:
            msg_obj = choice.get("message", {})
            content = str(msg_obj.get("content", "") if isinstance(msg_obj, dict) else "")
            blocked, score = parse_thinking_trace_verdict(content)
        else:
            score = parse_yes_no_logprob_score(choice)
            blocked = score >= self._threshold

        categories = [f"granite_{risk_criterion}"] if blocked else []
        wall_ms = (time.perf_counter() - start) * 1000.0

        return adapter_pb2.EvaluateResponse(
            blocked=blocked,
            risk_score=float(max(0.0, min(1.0, score))),
            redacted_text=request.text,
            spans=[],
            triggered_categories=categories,
            taint_state=adapter_pb2.SessionTaint(),
            usage=compute_usage_metrics(request.text, wall_ms),
            judge_graded=True,
        )

    def _select_criterion(self, request: adapter_pb2.EvaluateRequest) -> str:
        if request.direction == adapter_pb2.DIRECTION_TOOL_CALL:
            return "function_call"
        if request.direction == adapter_pb2.DIRECTION_OUTPUT:
            return "groundedness"
        return "jailbreak"

    async def _default_http_post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(payload).encode("utf-8")

        def _do_post() -> dict[str, Any]:
            req = urllib.request.Request(
                url,
                data=encoded,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout_sec) as resp:
                data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
                return data

        return await asyncio.to_thread(_do_post)

    async def _default_http_get(self, url: str) -> dict[str, Any]:
        def _do_get() -> dict[str, Any]:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self._timeout_sec) as resp:
                data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
                return data

        return await asyncio.to_thread(_do_get)
