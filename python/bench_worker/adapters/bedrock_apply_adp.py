"""AWS Bedrock ApplyGuardrail adapter (boto3 bedrock-runtime.apply_guardrail).

Implementation details:
  - Calls `apply_guardrail(..., outputScope="FULL")`.
  - Applies boto3 #4317 trailing newline normalization: strips a synthetic trailing
    `\n` appended by AWS Bedrock masking ONLY when the original input lacked one.
  - Extracts paid PII / content policy text units separately from free regex units.
  - Enforces configurable token-bucket concurrency, optional `--no-cache` headers,
    and isolates `ThrottlingException` from pure engine latency.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from bench_worker.adapters.base import (
    GuardrailAdapter,
    SpanSpec,
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
    map_direction_to_bedrock_source,
    normalize_bedrock_entity,
)
from bench_worker.gen.bench.v1 import adapter_pb2

_CONFIDENCE_TO_SCORE: dict[str, float] = {
    "NONE": 0.0,
    "LOW": 0.35,
    "MEDIUM": 0.65,
    "HIGH": 0.95,
}


def normalize_bedrock_trailing_newline(original_text: str, masked_text: str) -> str:
    """Workaround for AWS Bedrock ApplyGuardrail boto3 issue #4317.

    `bedrock-runtime.apply_guardrail` can append a single synthetic trailing `\\n`
    to `outputs[0]["text"]` when masking PII/secrets. Strip exactly one trailing
    `\\n` ONLY when `original_text` did not end with `\\n`.
    """
    if not original_text.endswith("\n") and masked_text.endswith("\n"):
        return masked_text[:-1]
    return masked_text


def _locate_match_spans(
    original_text: str, entity_type: str, match_text: str, confidence: float
) -> list[SpanSpec]:
    if not match_text:
        return []
    spans: list[SpanSpec] = []
    start = 0
    while True:
        idx = original_text.find(match_text, start)
        if idx < 0:
            break
        spans.append(
            SpanSpec(
                entity_type=entity_type,
                begin_offset=idx,
                end_offset=idx + len(match_text),
                confidence=confidence,
            )
        )
        start = idx + len(match_text)
    return spans


class BedrockApplyAdapter(GuardrailAdapter):
    """Plane 2 adapter wrapping AWS Bedrock Runtime `ApplyGuardrail`."""

    def __init__(
        self,
        *,
        guardrail_id: str | None = None,
        guardrail_version: str = "DRAFT",
        region_name: str = "us-east-1",
        boto_client: Any | None = None,
        rate_per_sec: float = 0.0,
        max_concurrency: int = 8,
        no_cache: bool = True,
    ) -> None:
        self.adapter_name = "bedrock_apply"
        self._guardrail_id = guardrail_id or os.environ.get("BEDROCK_GUARDRAIL_ID", "")
        self._guardrail_version = guardrail_version or os.environ.get(
            "BEDROCK_GUARDRAIL_VERSION", "DRAFT"
        )
        self._region_name = region_name
        self.model_version = f"apply-guardrail:{self._guardrail_version}"
        self._boto_client = boto_client
        self._no_cache = no_cache
        self._limiter = AsyncTokenBucket(
            rate_per_sec=rate_per_sec,
            burst=max(1, max_concurrency),
            max_concurrency=max_concurrency,
        )
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
        if not self._guardrail_id:
            raise RuntimeError(
                "BEDROCK_GUARDRAIL_ID (or --guardrail-id) must be configured for bedrock_apply."
            )
        self._get_client()
        return (self.adapter_name, self.model_version)

    async def reset_session(self, session_id: str) -> None:
        del session_id

    async def evaluate(
        self, request: adapter_pb2.EvaluateRequest
    ) -> adapter_pb2.EvaluateResponse:
        if not self._guardrail_id:
            raise RuntimeError("guardrail_id is required for bedrock_apply")

        client = self._get_client()
        source = map_direction_to_bedrock_source(request.direction)

        await self._limiter.acquire()
        try:
            start = time.perf_counter()
            try:
                raw_resp: dict[str, Any] = await asyncio.to_thread(
                    client.apply_guardrail,
                    guardrailIdentifier=self._guardrail_id,
                    guardrailVersion=self._guardrail_version,
                    source=source,
                    content=[{"text": {"text": request.text}}],
                    outputScope="FULL",
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

        return self._parse_response(request.text, raw_resp, wall_ms)

    def _parse_response(
        self, original_text: str, resp: dict[str, Any], wall_ms: float
    ) -> adapter_pb2.EvaluateResponse:
        action = str(resp.get("action", "NONE"))
        blocked = action == "GUARDRAIL_INTERVENED"

        # Normalize trailing newline quirk (boto3 #4317) before aligning redactions.
        redacted_text = original_text
        outputs = resp.get("outputs")
        if isinstance(outputs, list) and outputs:
            first_out = outputs[0]
            if isinstance(first_out, dict) and isinstance(first_out.get("text"), str):
                redacted_text = normalize_bedrock_trailing_newline(
                    original_text, first_out["text"]
                )

        categories: set[str] = set()
        raw_spans: list[SpanSpec] = []
        risk_score = 0.0

        assessments = resp.get("assessments")
        if isinstance(assessments, list):
            for assessment in assessments:
                if not isinstance(assessment, dict):
                    continue
                content_pol = assessment.get("contentPolicy")
                if isinstance(content_pol, dict):
                    for flt in content_pol.get("filters", []):
                        if not isinstance(flt, dict):
                            continue
                        conf = str(flt.get("confidence", "NONE")).upper()
                        f_type = str(flt.get("type", "CONTENT")).upper()
                        score = _CONFIDENCE_TO_SCORE.get(conf, 0.0)
                        risk_score = max(risk_score, score)
                        if flt.get("action") == "BLOCKED" or flt.get("detected"):
                            categories.add(f"bedrock_content_{f_type}")

                sens_pol = assessment.get("sensitiveInformationPolicy")
                if isinstance(sens_pol, dict):
                    for pii in sens_pol.get("piiEntities", []):
                        if not isinstance(pii, dict):
                            continue
                        ent = normalize_bedrock_entity(str(pii.get("type", "PII")))
                        match_str = str(pii.get("match", ""))
                        if pii.get("action") in ("ANONYMIZED", "BLOCKED") or pii.get("detected"):
                            categories.add(f"bedrock_pii_{ent}")
                            risk_score = max(risk_score, 0.90)
                            raw_spans.extend(
                                _locate_match_spans(original_text, ent, match_str, 0.92)
                            )
                    for rgx in sens_pol.get("regexes", []):
                        if not isinstance(rgx, dict):
                            continue
                        r_name = normalize_bedrock_entity(str(rgx.get("name", "REGEX_SECRET")))
                        match_str = str(rgx.get("match", ""))
                        if rgx.get("action") in ("ANONYMIZED", "BLOCKED") or rgx.get("detected"):
                            categories.add(f"bedrock_regex_{r_name}")
                            risk_score = max(risk_score, 0.95)
                            raw_spans.extend(
                                _locate_match_spans(original_text, r_name, match_str, 0.95)
                            )

                topic_pol = assessment.get("topicPolicy")
                if isinstance(topic_pol, dict):
                    for topic in topic_pol.get("topics", []):
                        if isinstance(topic, dict) and (
                            topic.get("action") == "BLOCKED" or topic.get("detected")
                        ):
                            categories.add(f"bedrock_topic_{topic.get('name', 'denied')}")
                            risk_score = max(risk_score, 0.90)

        if blocked and risk_score == 0.0:
            risk_score = 1.0

        # Extract authoritative AWS Bedrock usage billing units (distinguishing paid vs free regex).
        raw_usage = resp.get("usage")
        usage_dict: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        content_tu = int(usage_dict.get("contentPolicyUnits", 0) or 0)
        pii_paid_tu = int(usage_dict.get("sensitiveInformationPolicyUnits", 0) or 0)
        pii_free_tu = int(usage_dict.get("sensitiveInformationPolicyFreeUnits", 0) or 0)
        other_tu = (
            int(usage_dict.get("topicPolicyUnits", 0) or 0)
            + int(usage_dict.get("wordPolicyUnits", 0) or 0)
            + int(usage_dict.get("contextualGroundingPolicyUnits", 0) or 0)
            + int(usage_dict.get("automatedReasoningPolicyUnits", 0) or 0)
        )

        self.billing.requests_completed += 1
        self.billing.content_policy_units += content_tu
        self.billing.pii_paid_units += pii_paid_tu
        self.billing.pii_free_regex_units += pii_free_tu
        self.billing.other_policy_units += other_tu

        # Per-request billed text units: authoritative max paid policy units if returned,
        # else canonical ceil(chars / 1000) fallback.
        reported_tu = max(content_tu, pii_paid_tu, other_tu)
        billed_tu = reported_tu if reported_tu > 0 else compute_text_units(original_text)

        spans = normalize_spans(original_text, raw_spans)
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
