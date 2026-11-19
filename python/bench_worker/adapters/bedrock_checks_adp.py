"""AWS Bedrock InvokeGuardrailChecks adapter (boto3>=1.43.30).

Maps AWS `bedrock-runtime.invoke_guardrail_checks`:
  - Continuous `severityScore` (0.0 to 1.0) for `PROMPT_INJECTION`, `JAILBREAK`,
    `PROMPT_LEAKAGE`, and optional content filter categories.
  - Exact PII/secret character-offset spans (`beginOffset`, `endOffset`,
    `confidenceScore`) mapped into canonical `SpanFinding` + deterministic redaction.
  - Exact text-unit billing extraction matching the 2026 Bedrock rate cards
    ($0.08/1k TU prompt attack + $0.10/1k TU PII + $0.07/1k TU content).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from bench_worker.adapters.base import (
    GuardrailAdapter,
    SpanSpec,
    apply_span_redactions,
    compute_usage_metrics,
    normalize_spans,
    to_proto_spans,
)
from bench_worker.adapters.bedrock_common import (
    THROTTLE_ERROR_CODES,
    AsyncTokenBucket,
    BedrockBillingSnapshot,
    BedrockThrottledError,
    attach_no_cache_header,
    compute_text_units,
    extract_client_error_code,
    map_role_to_bedrock_checks_role,
    normalize_bedrock_entity,
)
from bench_worker.gen.bench.v1 import adapter_pb2

DEFAULT_PROMPT_ATTACK_CATEGORIES: tuple[str, ...] = (
    "PROMPT_INJECTION",
    "JAILBREAK",
    "PROMPT_LEAKAGE",
)
DEFAULT_SENSITIVE_ENTITIES: tuple[str, ...] = (
    "EMAIL",
    "PHONE",
    "US_SOCIAL_SECURITY_NUMBER",
    "NAME",
    "CREDIT_DEBIT_CARD_NUMBER",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
)
DEFAULT_CONTENT_CATEGORIES: tuple[str, ...] = (
    "HATE",
    "VIOLENCE",
    "MISCONDUCT",
    "INSULTS",
    "SEXUAL",
)


class BedrockChecksAdapter(GuardrailAdapter):
    """Plane 2 adapter wrapping AWS Bedrock Runtime `InvokeGuardrailChecks`."""

    def __init__(
        self,
        *,
        region_name: str = "us-east-1",
        boto_client: Any | None = None,
        threshold: float = 0.50,
        enable_content_filter: bool = False,
        rate_per_sec: float = 0.0,
        max_concurrency: int = 8,
        no_cache: bool = True,
    ) -> None:
        self.adapter_name = "bedrock_checks"
        self.model_version = "invoke-guardrail-checks:v1"
        self._region_name = region_name
        self._boto_client = boto_client
        self._threshold = threshold
        self._enable_content_filter = enable_content_filter
        self._no_cache = no_cache
        self._limiter = AsyncTokenBucket(
            rate_per_sec=rate_per_sec,
            burst=max(1, max_concurrency),
            max_concurrency=max_concurrency,
        )
        self._sessions: dict[str, list[dict[str, Any]]] = {}
        self.billing = BedrockBillingSnapshot()

        if self._boto_client is not None and self._no_cache:
            attach_no_cache_header(self._boto_client)

    def _get_client(self) -> Any:
        if self._boto_client is not None:
            return self._boto_client
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "boto3>=1.43.30 is required for Bedrock adapters. Install with: uv sync --extra aws"
            ) from exc
        client = boto3.client("bedrock-runtime", region_name=self._region_name)
        if self._no_cache:
            attach_no_cache_header(client)
        self._boto_client = client
        return client

    async def health(self) -> tuple[str, str]:
        client = self._get_client()
        if not hasattr(client, "invoke_guardrail_checks"):
            raise RuntimeError(
                "Installed boto3/botocore lacks invoke_guardrail_checks. "
                "Upgrade to boto3>=1.43.30."
            )
        return (self.adapter_name, self.model_version)

    async def reset_session(self, session_id: str) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    def _build_checks_payload(self) -> dict[str, Any]:
        checks: dict[str, Any] = {
            "promptAttack": {
                "categories": [{"category": c} for c in DEFAULT_PROMPT_ATTACK_CATEGORIES]
            },
            "sensitiveInformation": {
                "entities": [{"type": e} for e in DEFAULT_SENSITIVE_ENTITIES]
            },
        }
        if self._enable_content_filter:
            checks["contentFilter"] = {
                "categories": [{"category": c} for c in DEFAULT_CONTENT_CATEGORIES]
            }
        return checks

    async def evaluate(
        self, request: adapter_pb2.EvaluateRequest
    ) -> adapter_pb2.EvaluateResponse:
        client = self._get_client()
        role = map_role_to_bedrock_checks_role(request.role)
        current_msg: dict[str, Any] = {"role": role, "content": [{"text": request.text}]}

        history = self._sessions.setdefault(request.session_id, []) if request.session_id else []
        messages = [*history, current_msg]
        target_msg_index = len(messages) - 1
        if request.session_id:
            history.append(current_msg)

        checks_cfg = self._build_checks_payload()

        await self._limiter.acquire()
        try:
            start = time.perf_counter()
            try:
                raw_resp: dict[str, Any] = await asyncio.to_thread(
                    client.invoke_guardrail_checks,
                    messages=messages,
                    checks=checks_cfg,
                )
            except Exception as exc:
                err_info = extract_client_error_code(exc)
                if err_info and err_info[0] in THROTTLE_ERROR_CODES:
                    self.billing.throttled_count += 1
                    raise BedrockThrottledError(err_info[0], err_info[1]) from exc
                raise
            wall_ms = (time.perf_counter() - start) * 1000.0
        finally:
            self._limiter.release()

        return self._parse_response(request.text, target_msg_index, raw_resp, wall_ms)

    def _parse_response(
        self,
        original_text: str,
        target_msg_index: int,
        resp: dict[str, Any],
        wall_ms: float,
    ) -> adapter_pb2.EvaluateResponse:
        raw_results = resp.get("results")
        results: dict[str, Any] = raw_results if isinstance(raw_results, dict) else {}
        categories: set[str] = set()
        raw_spans: list[SpanSpec] = []
        risk_score = 0.0

        # 1. Prompt attack continuous severityScore (0.0 .. 1.0)
        pa_block = results.get("promptAttack")
        if isinstance(pa_block, dict):
            for entry in pa_block.get("results", []):
                if not isinstance(entry, dict):
                    continue
                sev = float(entry.get("severityScore", 0.0))
                cat = str(entry.get("category", "PROMPT_INJECTION")).upper()
                risk_score = max(risk_score, sev)
                if sev >= self._threshold:
                    categories.add(f"bedrock_checks_{cat}")

        # 2. Content filter continuous severityScore (optional)
        cf_block = results.get("contentFilter")
        if isinstance(cf_block, dict):
            for entry in cf_block.get("results", []):
                if not isinstance(entry, dict):
                    continue
                sev = float(entry.get("severityScore", 0.0))
                cat = str(entry.get("category", "CONTENT")).upper()
                risk_score = max(risk_score, sev)
                if sev >= self._threshold:
                    categories.add(f"bedrock_checks_content_{cat}")

        # 3. Sensitive information character spans (beginOffset / endOffset)
        si_block = results.get("sensitiveInformation")
        if isinstance(si_block, dict):
            for entry in si_block.get("results", []):
                if not isinstance(entry, dict):
                    continue
                msg_idx = entry.get("messageIndex")
                if msg_idx is not None and int(msg_idx) != target_msg_index:
                    continue
                ent = normalize_bedrock_entity(str(entry.get("type", "PII")))
                begin = int(entry.get("beginOffset", -1))
                end = int(entry.get("endOffset", -1))
                conf = float(entry.get("confidenceScore", 0.90))
                if 0 <= begin < end <= len(original_text):
                    raw_spans.append(
                        SpanSpec(
                            entity_type=ent,
                            begin_offset=begin,
                            end_offset=end,
                            confidence=conf,
                        )
                    )
                    categories.add(f"bedrock_checks_pii_{ent}")
                    risk_score = max(risk_score, conf)

        spans = normalize_spans(original_text, raw_spans)
        redacted_text = apply_span_redactions(original_text, spans)
        blocked = risk_score >= self._threshold or len(spans) > 0

        # 4. Authoritative usage billing text units
        raw_usage = resp.get("usage")
        usage_dict: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        pa_tu = int((usage_dict.get("promptAttack") or {}).get("textUnits", 0) or 0)
        si_tu = int((usage_dict.get("sensitiveInformation") or {}).get("textUnits", 0) or 0)
        cf_tu = int((usage_dict.get("contentFilter") or {}).get("textUnits", 0) or 0)

        self.billing.requests_completed += 1
        self.billing.prompt_attack_units += pa_tu
        self.billing.pii_paid_units += si_tu
        self.billing.content_policy_units += cf_tu

        reported_tu = max(pa_tu, si_tu, cf_tu)
        billed_tu = reported_tu if reported_tu > 0 else compute_text_units(original_text)

        usage_proto = compute_usage_metrics(original_text, wall_ms)
        usage_proto.text_units_billed = billed_tu

        return adapter_pb2.EvaluateResponse(
            blocked=blocked,
            risk_score=float(max(0.0, min(1.0, risk_score))),
            redacted_text=redacted_text,
            spans=to_proto_spans(spans),
            triggered_categories=sorted(categories),
            taint_state=adapter_pb2.SessionTaint(),
            usage=usage_proto,
            judge_graded=False,
        )
