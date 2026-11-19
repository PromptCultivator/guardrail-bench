"""Verification tests for Python protobuf stubs and smoke fixtures."""

from __future__ import annotations

import hashlib
import json
import tempfile
from concurrent import futures
from pathlib import Path
from typing import Any

import grpc

from bench_worker.gen.bench.v1 import adapter_pb2, adapter_pb2_grpc

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "datasets" / "fixtures" / "smoke_50.jsonl"
MANIFEST_PATH = REPO_ROOT / "datasets" / "manifests" / "smoke_50.manifest.json"


class _StubAdapterServicer(adapter_pb2_grpc.AdapterServiceServicer):
    def Health(  # noqa: N802
        self,
        request: adapter_pb2.HealthRequest,
        context: grpc.ServicerContext,
    ) -> adapter_pb2.HealthResponse:
        del request, context
        return adapter_pb2.HealthResponse(
            adapter_name="python_smoke_stub",
            model_version="0.1.0",
        )

    def ResetSession(  # noqa: N802
        self,
        request: adapter_pb2.ResetSessionRequest,
        context: grpc.ServicerContext,
    ) -> adapter_pb2.ResetSessionResponse:
        del request, context
        return adapter_pb2.ResetSessionResponse()

    def Evaluate(  # noqa: N802
        self,
        request: adapter_pb2.EvaluateRequest,
        context: grpc.ServicerContext,
    ) -> adapter_pb2.EvaluateResponse:
        del context
        chars = len(request.text)
        text_units = max(1, (chars + 999) // 1000)
        return adapter_pb2.EvaluateResponse(
            blocked=False,
            risk_score=0.02,
            redacted_text=request.text,
            taint_state=adapter_pb2.SessionTaint(
                reads_private=False,
                reads_untrusted=False,
                sends_out=False,
                trifecta_triggered=False,
            ),
            usage=adapter_pb2.UsageMetrics(
                input_chars=chars,
                text_units_billed=text_units,
                input_tokens=chars // 4,
                adapter_wall_ms=0.15,
            ),
            judge_graded=False,
        )


def test_proto_optional_fields_and_serialization() -> None:
    req = adapter_pb2.EvaluateRequest(
        sample_id="t3-mcp-0001",
        session_id="sess-py-1",
        turn_index=0,
        direction=adapter_pb2.DIRECTION_TOOL_RESULT,
        role="tool",
        text="José Nuñez — canary check",
        mcp_tool=adapter_pb2.ToolAnnotations(
            tool_name="read_file",
            server_name="filesystem",
            read_only_hint=True,
            trusted_server=True,
        ),
    )

    wire = req.SerializeToString()
    decoded = adapter_pb2.EvaluateRequest()
    decoded.ParseFromString(wire)

    assert decoded.HasField("mcp_tool")
    assert decoded.mcp_tool.HasField("read_only_hint")
    assert decoded.mcp_tool.read_only_hint is True
    assert not decoded.mcp_tool.HasField("open_world_hint")
    assert decoded.mcp_tool.trusted_server is True


def test_grpc_unix_domain_socket_roundtrip() -> None:
    # macOS sun_path is capped at 104 bytes; use a short temp directory under /tmp.
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="gb-") as sock_dir:
        sock_path = Path(sock_dir) / "a.sock"
        target = f"unix://{sock_path}"

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        adapter_pb2_grpc.add_AdapterServiceServicer_to_server(_StubAdapterServicer(), server)
        server.add_insecure_port(target)
        server.start()
        try:
            with grpc.insecure_channel(target) as channel:
                stub = adapter_pb2_grpc.AdapterServiceStub(channel)

                health = stub.Health(adapter_pb2.HealthRequest())
                assert health.adapter_name == "python_smoke_stub"
                assert health.model_version == "0.1.0"

                resp = stub.Evaluate(
                    adapter_pb2.EvaluateRequest(
                        sample_id="t1-benign-0001",
                        session_id="sess-uds",
                        turn_index=0,
                        direction=adapter_pb2.DIRECTION_INPUT,
                        role="user",
                        text="Explain Envoy ext_proc streaming.",
                    )
                )
                assert resp.blocked is False
                assert resp.usage.input_chars == len("Explain Envoy ext_proc streaming.")
                assert resp.usage.text_units_billed == 1

                stub.ResetSession(adapter_pb2.ResetSessionRequest(session_id="sess-uds"))
        finally:
            server.stop(grace=0)


def test_smoke_50_fixture_and_manifest_parity() -> None:
    manifest: dict[str, Any] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    raw = FIXTURE_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]

    rows: list[dict[str, Any]] = [
        json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()
    ]
    assert len(rows) == 50
    assert manifest["row_count"] == 50

    track_counts: dict[str, int] = {}
    valid_directions = {
        "DIRECTION_INPUT",
        "DIRECTION_OUTPUT",
        "DIRECTION_TOOL_CALL",
        "DIRECTION_TOOL_RESULT",
    }

    for row in rows:
        track = row["track"]
        track_counts[track] = track_counts.get(track, 0) + 1
        turns = row["turns"]
        assert len(turns) >= 1
        for idx, turn in enumerate(turns):
            assert turn["turn_index"] == idx
            assert turn["direction"] in valid_directions

        turn0_text: str = turns[0]["text"]
        for span in row["ground_truth_spans"]:
            begin = span["begin_offset"]
            end = span["end_offset"]
            assert 0 <= begin < end <= len(turn0_text)
            if row["sample_id"] == "t2-pii-0003" and span["entity_type"] == "PERSON":
                assert turn0_text[begin:end] == "José Nuñez"
            if row["sample_id"] == "t2-pii-0003" and span["entity_type"] == "EMAIL":
                assert turn0_text[begin:end] == "jose.nunez@example.org"

    assert track_counts == {
        "prompt_injection": 20,
        "redaction": 15,
        "mcp_trifecta": 15,
    }
    assert manifest["track_counts"] == track_counts
