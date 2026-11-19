"""Asyncio gRPC server hosting Plane 2 Python guardrail adapters over UDS or TCP."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
from collections.abc import Sequence
from pathlib import Path

import grpc

from bench_worker.adapters.base import GuardrailAdapter
from bench_worker.adapters.bedrock_apply_adp import BedrockApplyAdapter
from bench_worker.adapters.bedrock_checks_adp import BedrockChecksAdapter
from bench_worker.adapters.bedrock_common import BedrockThrottledError
from bench_worker.adapters.granite_adp import DEFAULT_VLLM_BASE_URL, GraniteGuardianAdapter
from bench_worker.adapters.llamafirewall_adp import LlamaFirewallAdapter
from bench_worker.adapters.nemo_presidio_adp import NemoPresidioAdapter
from bench_worker.adapters.piguard_adp import PIGuardAdapter
from bench_worker.gen.bench.v1 import adapter_pb2, adapter_pb2_grpc


class AdapterServiceServicer(adapter_pb2_grpc.AdapterServiceServicer):
    """Bridges gRPC AdapterService RPCs onto any GuardrailAdapter implementation."""

    def __init__(self, adapter: GuardrailAdapter) -> None:
        self._adapter = adapter

    async def Health(  # noqa: N802
        self,
        request: adapter_pb2.HealthRequest,
        context: grpc.aio.ServicerContext[adapter_pb2.HealthRequest, adapter_pb2.HealthResponse],
    ) -> adapter_pb2.HealthResponse:
        del request
        try:
            name, version = await self._adapter.health()
        except Exception as exc:
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))
            raise AssertionError("unreachable") from exc  # pragma: no cover
        return adapter_pb2.HealthResponse(adapter_name=name, model_version=version)

    async def ResetSession(  # noqa: N802
        self,
        request: adapter_pb2.ResetSessionRequest,
        context: grpc.aio.ServicerContext[
            adapter_pb2.ResetSessionRequest, adapter_pb2.ResetSessionResponse
        ],
    ) -> adapter_pb2.ResetSessionResponse:
        del context
        await self._adapter.reset_session(request.session_id)
        return adapter_pb2.ResetSessionResponse()

    async def Evaluate(  # noqa: N802
        self,
        request: adapter_pb2.EvaluateRequest,
        context: grpc.aio.ServicerContext[
            adapter_pb2.EvaluateRequest, adapter_pb2.EvaluateResponse
        ],
    ) -> adapter_pb2.EvaluateResponse:
        try:
            return await self._adapter.evaluate(request)
        except BedrockThrottledError as exc:
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, str(exc))
            raise AssertionError("unreachable") from exc  # pragma: no cover
        except Exception as exc:
            await context.abort(grpc.StatusCode.INTERNAL, str(exc))
            raise AssertionError("unreachable") from exc  # pragma: no cover


def build_adapter(
    adapter_id: str,
    *,
    use_mock: bool = False,
    vllm_url: str = DEFAULT_VLLM_BASE_URL,
    thinking_mode: bool = False,
    enable_dialog_rails: bool = False,
    aws_region: str = "us-east-1",
    guardrail_id: str | None = None,
    guardrail_version: str = "DRAFT",
    bedrock_rps: float = 0.0,
    bedrock_concurrency: int = 8,
    no_cache: bool = True,
) -> GuardrailAdapter:
    """Instantiates a registered Plane 2 guardrail adapter by canonical adapter_id."""
    key = adapter_id.strip().lower()
    if key == "llamafirewall":
        return LlamaFirewallAdapter(use_mock=use_mock)
    if key == "nemo_presidio":
        return NemoPresidioAdapter(
            use_mock=use_mock, enable_dialog_rails=enable_dialog_rails
        )
    if key == "piguard":
        return PIGuardAdapter(use_mock=use_mock)
    if key == "granite_guardian":
        return GraniteGuardianAdapter(
            base_url=vllm_url, thinking_mode=thinking_mode, use_mock=use_mock
        )
    if key == "bedrock_apply":
        return BedrockApplyAdapter(
            guardrail_id=guardrail_id,
            guardrail_version=guardrail_version,
            region_name=aws_region,
            rate_per_sec=bedrock_rps,
            max_concurrency=bedrock_concurrency,
            no_cache=no_cache,
        )
    if key == "bedrock_checks":
        return BedrockChecksAdapter(
            region_name=aws_region,
            rate_per_sec=bedrock_rps,
            max_concurrency=bedrock_concurrency,
            no_cache=no_cache,
        )
    raise ValueError(
        f"Unknown Python adapter {adapter_id!r}. "
        "Supported adapters: llamafirewall, nemo_presidio, piguard, granite_guardian, "
        "bedrock_apply, bedrock_checks."
    )


async def create_aio_server(
    adapter: GuardrailAdapter, listen_addr: str
) -> tuple[grpc.aio.Server, str]:
    """Creates and binds a grpc.aio.Server on a Unix domain socket or TCP port."""
    if listen_addr.startswith("unix://"):
        sock_path = Path(listen_addr[len("unix://") :])
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        if sock_path.exists():
            sock_path.unlink()

    server = grpc.aio.server()
    adapter_pb2_grpc.add_AdapterServiceServicer_to_server(
        AdapterServiceServicer(adapter), server
    )
    bound_port = server.add_insecure_port(listen_addr)
    if bound_port == 0 and not listen_addr.startswith("unix://"):
        raise RuntimeError(f"Failed to bind gRPC server on {listen_addr!r}")
    await server.start()

    actual_addr = listen_addr
    if not listen_addr.startswith("unix://") and listen_addr.endswith(":0"):
        host = listen_addr.rsplit(":", 1)[0]
        actual_addr = f"{host}:{bound_port}"
    return server, actual_addr


async def serve_forever(adapter: GuardrailAdapter, listen_addr: str) -> None:
    """Runs the asyncio gRPC worker until SIGINT or SIGTERM."""
    server, actual_addr = await create_aio_server(adapter, listen_addr)
    print(
        f"bench_worker serving adapter={adapter.adapter_name} "
        f"version={adapter.model_version} on {actual_addr}",
        flush=True,
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()
    await server.stop(grace=2.0)

    if listen_addr.startswith("unix://"):
        sock_path = Path(listen_addr[len("unix://") :])
        if sock_path.exists():
            sock_path.unlink()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plane 2 asyncio gRPC worker hosting Python guardrail adapters."
    )
    parser.add_argument(
        "--adapter",
        required=True,
        choices=(
            "llamafirewall",
            "nemo_presidio",
            "piguard",
            "granite_guardian",
            "bedrock_apply",
            "bedrock_checks",
        ),
        help="Guardrail adapter ID to serve.",
    )
    parser.add_argument(
        "--listen",
        default="unix:///tmp/gb-worker.sock",
        help="gRPC listen address (unix:///tmp/...sock or 127.0.0.1:50051).",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use deterministic offline mock model weights (for CI without GPUs).",
    )
    parser.add_argument(
        "--vllm-url",
        default=DEFAULT_VLLM_BASE_URL,
        help="OpenAI-compatible vLLM base URL for granite_guardian.",
    )
    parser.add_argument(
        "--thinking-mode",
        action="store_true",
        help="Enable thinking-trace mode for granite_guardian.",
    )
    parser.add_argument(
        "--enable-dialog-rails",
        action="store_true",
        help="Enable NeMo LLMRails dialog rail on top of Presidio.",
    )
    parser.add_argument(
        "--aws-region",
        default="us-east-1",
        help="AWS region for Bedrock adapters (default: us-east-1).",
    )
    parser.add_argument(
        "--guardrail-id",
        default=None,
        help="Bedrock Guardrail identifier for bedrock_apply (or BEDROCK_GUARDRAIL_ID env).",
    )
    parser.add_argument(
        "--guardrail-version",
        default="DRAFT",
        help="Bedrock Guardrail version for bedrock_apply (default: DRAFT).",
    )
    parser.add_argument(
        "--bedrock-rps",
        type=float,
        default=0.0,
        help="Token-bucket requests/sec cap for AWS Bedrock adapters (0 = unlimited).",
    )
    parser.add_argument(
        "--bedrock-concurrency",
        type=int,
        default=8,
        help="Max concurrent in-flight AWS Bedrock requests (default: 8).",
    )
    parser.add_argument(
        "--no-cache",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Send Cache-Control: no-cache headers on AWS Bedrock requests (default: true).",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    adapter = build_adapter(
        args.adapter,
        use_mock=args.mock,
        vllm_url=args.vllm_url,
        thinking_mode=args.thinking_mode,
        enable_dialog_rails=args.enable_dialog_rails,
        aws_region=args.aws_region,
        guardrail_id=args.guardrail_id,
        guardrail_version=args.guardrail_version,
        bedrock_rps=args.bedrock_rps,
        bedrock_concurrency=args.bedrock_concurrency,
        no_cache=args.no_cache,
    )
    asyncio.run(serve_forever(adapter, args.listen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
