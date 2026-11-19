"""Shared AWS Bedrock utilities: rate limiting, throttling telemetry, --no-cache, billing."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from typing import Any

from bench_worker.gen.bench.v1 import adapter_pb2

# Canonical mapping from AWS Bedrock PII entity types to guardrail-bench SpanFinding labels.
BEDROCK_ENTITY_MAP: dict[str, str] = {
    "EMAIL": "EMAIL",
    "PHONE": "PHONE_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER": "SSN",
    "NAME": "PERSON",
    "CREDIT_DEBIT_CARD_NUMBER": "CREDIT_CARD",
    "AWS_ACCESS_KEY": "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY": "AWS_SECRET_KEY",
    "IP_ADDRESS": "IP_ADDRESS",
    "PASSWORD": "PASSWORD",
    "USERNAME": "USERNAME",
}

THROTTLE_ERROR_CODES = frozenset(
    {
        "ThrottlingException",
        "TooManyRequestsException",
        "LimitExceededException",
        "ServiceUnavailableException",
    }
)


class BedrockThrottledError(RuntimeError):
    """Raised when AWS Bedrock throttles a call so throttle events stay separate from latency."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"AWS Bedrock throttled ({code}): {message}")
        self.error_code = code


@dataclass
class BedrockBillingSnapshot:
    """Tracks cumulative billed text units and separate throttle counts across an adapter run."""

    requests_completed: int = 0
    throttled_count: int = 0
    prompt_attack_units: int = 0
    pii_paid_units: int = 0
    pii_free_regex_units: int = 0
    content_policy_units: int = 0
    other_policy_units: int = 0

    def estimated_cost_usd(self, api_mode: str) -> float:
        """Computes exact USD cost under verified 2026 Bedrock rate cards."""
        if api_mode == "bedrock_checks":
            return round(
                (self.prompt_attack_units / 1000.0) * 0.08
                + (self.pii_paid_units / 1000.0) * 0.10
                + (self.content_policy_units / 1000.0) * 0.07,
                6,
            )
        # bedrock_apply: $0.15/1k TU content + $0.10/1k TU paid PII (regex free)
        return round(
            (self.content_policy_units / 1000.0) * 0.15
            + (self.pii_paid_units / 1000.0) * 0.10,
            6,
        )


class AsyncTokenBucket:
    """Async token-bucket rate limiter + concurrency guard for AWS Bedrock APIs."""

    def __init__(
        self,
        *,
        rate_per_sec: float = 0.0,
        burst: int = 1,
        max_concurrency: int = 8,
    ) -> None:
        self._rate = max(0.0, float(rate_per_sec))
        self._capacity = float(max(1, burst))
        self._tokens = self._capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def acquire(self) -> None:
        await self._semaphore.acquire()
        if self._rate <= 0.0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = max(0.0, now - self._last_refill)
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_sec = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait_sec)

    def release(self) -> None:
        self._semaphore.release()


def compute_text_units(text: str) -> int:
    """Computes Bedrock billing text units: ceil(len(text) / 1000), minimum 1."""
    if not text:
        return 1
    return max(1, math.ceil(len(text) / 1000))


def map_direction_to_bedrock_source(direction: int) -> str:
    """Maps bench.v1.Direction to AWS ApplyGuardrail source ('INPUT' or 'OUTPUT')."""
    if direction == adapter_pb2.DIRECTION_OUTPUT:
        return "OUTPUT"
    return "INPUT"


def map_role_to_bedrock_checks_role(role: str) -> str:
    """Maps request.role to valid InvokeGuardrailChecks roles ('user', 'assistant', 'system')."""
    lowered = (role or "user").strip().lower()
    if lowered in ("user", "assistant", "system"):
        return lowered
    # MCP tool outputs/calls map cleanly to user/assistant context for Bedrock Checks validation.
    return "user"


def attach_no_cache_header(boto_client: Any) -> None:
    """Registers a botocore event hook injecting Cache-Control: no-cache, no-store headers."""

    def _inject_no_cache(request: Any, **kwargs: Any) -> None:
        del kwargs
        headers = getattr(request, "headers", None)
        if headers is not None:
            headers["Cache-Control"] = "no-cache, no-store"
            headers["Pragma"] = "no-cache"

    events = getattr(getattr(boto_client, "meta", None), "events", None)
    if events is not None:
        events.register("before-sign.bedrock-runtime.*", _inject_no_cache)


def normalize_bedrock_entity(entity_type: str) -> str:
    """Maps AWS Bedrock sensitive entity names into canonical SpanFinding entity_type strings."""
    upper = entity_type.strip().upper()
    return BEDROCK_ENTITY_MAP.get(upper, upper)


def extract_client_error_code(exc: Exception) -> tuple[str, str] | None:
    """Extracts AWS ClientError (code, message) if exc is a botocore ClientError."""
    resp = getattr(exc, "response", None)
    if not isinstance(resp, dict):
        return None
    err = resp.get("Error")
    if not isinstance(err, dict):
        return None
    code = str(err.get("Code", ""))
    msg = str(err.get("Message", str(exc)))
    return (code, msg) if code else None
